"""
Evil-twin access points, and the kernel settings an on-path attacker needs.

Two problems this module used to have, both of which left it Active and blind:

* The access point was read with ``iwgetid`` alone. That tool comes from
  wireless-tools, a package modern distributions no longer install by default,
  and its failure path is silent: no SSID, no BSSID, no alert, ever. It now
  falls back to ``iw`` and then to ``nmcli``, either of which is present on
  any machine that can join a WiFi network at all.

* Everything, including the ICMP-redirect check, was gated on the monitored
  interface being wireless. On a wired machine the module therefore did
  literally nothing while reporting itself active. Redirect acceptance is a
  route-hijack primitive on *any* link type — a switch is no safer than an
  access point here — so that check now runs regardless, and re-runs, because
  the setting can be changed after startup.
"""
import asyncio
import json
import os
import re
import subprocess
from pathlib import Path

from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import FAIL, INFO, PASS, Verdict, merge
from maze.utils.logger import log

_BSSID_CONFIRM_COUNT = 3   # a new BSSID must persist across this many checks
_AP_POLL = 15              # seconds between access-point reads
_REDIRECT_POLL = 300       # seconds between kernel-setting re-checks

# Access points already accepted for each SSID, kept across restarts. Without
# it every login re-learned the network from one BSSID, and the second band
# of the home router was a "possible Evil Twin" again on the next roam.
_KNOWN_FILE = Path.home() / ".config" / "maze" / "known-aps.json"
_KNOWN_MAX_SSIDS = 64
_KNOWN_MAX_BSSIDS = 32

_MAC_RE = re.compile(r'\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b')

# Kernel knobs that decide whether a stranger on the link can reroute traffic.
# "all" and the interface itself both have to be off for the setting to be off,
# which is why each is inspected rather than just the interface's copy.
_REDIRECT_KEYS = [
    ("ipv4", "accept_redirects",
     "an attacker on this network can reroute your traffic"),
    ("ipv6", "accept_redirects",
     "an attacker on this network can reroute your IPv6 traffic"),
]


def _is_wireless(interface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{interface}/wireless")


def _octets(mac: str) -> list[int]:
    return [int(part, 16) for part in mac.split(":")]


def _same_vendor(a: str, b: str) -> bool:
    """Whether two BSSIDs plausibly belong to one manufacturer's hardware.

    Access points derive their per-band and per-SSID BSSIDs from one base MAC,
    either by bumping the low bits or by setting the locally-administered bit
    of the first octet — so the vendor prefix, with that bit masked, matches.
    A mesh node from the same kit shares it too. An impostor can copy a prefix,
    but most evil-twin setups run on whatever card the attacker has, and a
    different vendor on a known SSID is the case worth raising.
    """
    try:
        x, y = _octets(a), _octets(b)
    except ValueError:
        return False
    if len(x) != 6 or len(y) != 6:
        return False
    if (x[0] | 0x02) == (y[0] | 0x02) and x[1:3] == y[1:3]:
        return True
    # Some vendors put the band index in the first octet (0x02, 0x06, 0x0a …)
    # and keep the rest of the base MAC: the NIC-specific tail then matches.
    return x[3:5] == y[3:5] and bool((x[0] | y[0]) & 0x02)


def _load_known() -> dict[str, list[str]]:
    try:
        data = json.loads(_KNOWN_FILE.read_text())
        return {str(k): [str(b) for b in v][:_KNOWN_MAX_BSSIDS]
                for k, v in data.items() if isinstance(v, list)}
    except Exception:
        return {}


def _save_known(known: dict[str, list[str]]) -> None:
    try:
        _KNOWN_FILE.parent.mkdir(parents=True, exist_ok=True)
        items = list(known.items())[-_KNOWN_MAX_SSIDS:]
        tmp = _KNOWN_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(items)))
        os.chmod(tmp, 0o600)
        tmp.replace(_KNOWN_FILE)
    except Exception as exc:
        log.debug(f"RogueAPDetector: could not save known APs — {exc}")


class RogueAPDetector:
    """Detect Evil Twin / rogue access points, and route-hijack exposure.

    A genuine multi-AP network (mesh, campus, office) shares one SSID across
    dozens of BSSIDs, and roaming between them is normal. The BSSID set for the
    current SSID therefore only ever grows, and an alert needs a genuinely new
    BSSID that persists across several confirmation cycles — a single blip or
    an ordinary roam is not enough.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._is_wifi = _is_wireless(interface)
        self._known_bssids: set[str] = set()
        self._known_ssid: str | None = None
        self._pending_bssid: str | None = None
        self._pending_count: int = 0
        self._warned_redirects: set[str] = set()
        self._ap_source: str = ""      # which tool answered, for the UI
        self._bus: EventBus | None = None
        self._persisted: dict[str, list[str]] | None = None   # lazy
        self._task: asyncio.Task | None = None
        self._redirect_task: asyncio.Task | None = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        # The link can change type between runs (dock plugged in, WiFi off), so
        # this is re-read at start rather than trusted from construction time.
        self._is_wifi = _is_wireless(self.interface)
        if self._is_wifi:
            ssid, bssid = await asyncio.to_thread(self._current_ap)
            if ssid:
                self._adopt(ssid, bssid)
            if not ssid:
                log.warning(
                    "RogueAPDetector: no tool on this system could read the "
                    "current access point (tried iw, iwgetid, nmcli) — "
                    "evil-twin detection is unavailable")
        self._task = asyncio.create_task(self._monitor())
        self._redirect_task = asyncio.create_task(self._redirect_loop())

    async def stop(self) -> None:
        for task in (self._task, self._redirect_task):
            if task:
                task.cancel()
        self._task = self._redirect_task = None

    # ── what the interface shows ─────────────────────────────────────────

    def status_detail(self) -> str:
        if not self._is_wifi:
            return (f"{self.interface} is not wireless — no access point to "
                    f"watch; ICMP redirect exposure still checked")
        if not self._known_ssid:
            return "cannot read the access point — evil-twin detection is blind"
        return (f"{self._known_ssid}: {len(self._known_bssids)} known "
                f"BSSID{'s' if len(self._known_bssids) != 1 else ''}"
                + (f" (via {self._ap_source})" if self._ap_source else ""))

    # ── self-test ────────────────────────────────────────────────────────

    async def verify(self) -> Verdict:
        """Two questions, and neither is answered from this module's memory.

        The kernel is asked whether it would honour an ICMP redirect — which
        decides whether a stranger on the link can reroute this machine's
        traffic — and the wireless stack is asked which access point we are on,
        which is the baseline an evil twin is detected against.
        """
        exposed: list[str] = []
        for family, key, _consequence in _REDIRECT_KEYS:
            exposed += await asyncio.to_thread(self._enabled_scopes, family, key)
        if exposed:
            redirects = Verdict(FAIL,
                                "this kernel accepts ICMP redirects: anyone on "
                                "the network can reroute this machine's traffic "
                                "through themselves", exposed)
        else:
            redirects = Verdict(PASS,
                                "ICMP redirects are refused on every scope, so "
                                "route hijacking by that route is not possible",
                                [f"checked all and {self.interface}, "
                                 f"IPv4 and IPv6"])

        if not self._is_wifi:
            ap = Verdict(INFO,
                         f"{self.interface} is not wireless, so there is no "
                         f"access point to watch — evil-twin detection applies "
                         f"to WiFi links only")
        else:
            ssid, bssid = await asyncio.to_thread(self._current_ap)
            if not ssid or not bssid:
                ap = Verdict(FAIL,
                             "no tool on this system could read the current "
                             "access point (tried iw, iwgetid, nmcli) — "
                             "evil-twin detection has no baseline and is blind")
            else:
                known = self._known_bssids | {bssid}
                ap = Verdict(PASS,
                             f"connected to '{ssid}' via {bssid}; "
                             f"{len(known)} BSSID(s) known for this network",
                             [f"read with {self._ap_source or 'iw'}"])
        return merge(redirects, ap)

    # ── access point identity ────────────────────────────────────────────

    def _current_ap(self) -> tuple[str | None, str | None]:
        """(SSID, BSSID) of the network we are on, from whichever tool answers.

        Blocking — always call through a thread.
        """
        for name, reader in (("iw", self._ap_via_iw),
                             ("iwgetid", self._ap_via_iwgetid),
                             ("nmcli", self._ap_via_nmcli)):
            try:
                ssid, bssid = reader()
            except Exception as exc:
                log.debug(f"RogueAPDetector: {name} failed — {exc}")
                continue
            if ssid and bssid:
                self._ap_source = name
                return ssid, bssid.lower()
        return None, None

    def _ap_via_iw(self) -> tuple[str | None, str | None]:
        """`iw dev <iface> link` — present wherever modern WiFi works.

        Output starts "Connected to <bssid> (on <iface>)" and carries an
        "SSID: <name>" line; when the interface is down it says "Not connected."
        """
        out = subprocess.check_output(
            ["iw", "dev", self.interface, "link"], text=True,
            timeout=3, stderr=subprocess.DEVNULL)
        if "not connected" in out.lower():
            return None, None
        bssid = _MAC_RE.search(out)
        ssid = re.search(r'^\s*SSID:\s*(.+)$', out, re.MULTILINE)
        return (ssid.group(1).strip() if ssid else None,
                bssid.group(1) if bssid else None)

    def _ap_via_iwgetid(self) -> tuple[str | None, str | None]:
        ssid = subprocess.check_output(
            ["iwgetid", self.interface, "--raw"], text=True,
            timeout=3, stderr=subprocess.DEVNULL).strip()
        bssid = subprocess.check_output(
            ["iwgetid", self.interface, "--ap", "--raw"], text=True,
            timeout=3, stderr=subprocess.DEVNULL).strip()
        return ssid or None, bssid or None

    def _ap_via_nmcli(self) -> tuple[str | None, str | None]:
        """NetworkManager's view. The active row is the one marked IN-USE.

        Colons inside the BSSID are escaped by --terse, so the field split has
        to respect the backslashes rather than splitting on every colon.
        """
        out = subprocess.check_output(
            ["nmcli", "--terse", "--fields", "IN-USE,SSID,BSSID",
             "dev", "wifi", "list", "ifname", self.interface],
            text=True, timeout=5, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if not line.startswith("*"):
                continue
            fields = re.split(r'(?<!\\):', line)
            ssid = fields[1].replace("\\:", ":") if len(fields) > 1 else ""
            bssid = _MAC_RE.search(line.replace("\\", ""))
            if ssid and bssid:
                return ssid, bssid.group(1)
        return None, None

    # ── access point monitoring ──────────────────────────────────────────

    async def _monitor(self) -> None:
        while True:
            await asyncio.sleep(_AP_POLL)
            if not self._is_wifi:
                # Re-check: an interface can gain a wireless directory only by
                # being replaced, but the configured interface itself may have
                # been switched while we ran.
                self._is_wifi = _is_wireless(self.interface)
                continue
            try:
                ssid, bssid = await asyncio.to_thread(self._current_ap)
            except Exception:
                continue
            if not ssid or not bssid:
                self._pending_bssid = None
                self._pending_count = 0
                continue
            if self._known_ssid and ssid == self._known_ssid:
                await self._check_bssid(ssid, bssid)
            else:
                # A different network: its own baseline, from what we already
                # know of it plus the access point we joined through.
                self._adopt(ssid, bssid)

    # ── baselines ────────────────────────────────────────────────────────

    def _known_for(self, ssid: str) -> list[str]:
        if self._persisted is None:
            self._persisted = _load_known()
        return self._persisted.get(ssid, [])

    def _adopt(self, ssid: str, bssid: str | None) -> None:
        self._known_ssid = ssid
        self._known_bssids = set(self._known_for(ssid))
        if bssid:
            self._remember(ssid, bssid)
        self._pending_bssid = None
        self._pending_count = 0

    def _remember(self, ssid: str, bssid: str) -> None:
        self._known_bssids.add(bssid)
        if self._persisted is None:
            self._persisted = _load_known()
        entry = [b for b in self._persisted.pop(ssid, []) if b != bssid]
        entry.append(bssid)
        self._persisted[ssid] = entry[-_KNOWN_MAX_BSSIDS:]   # most recent last
        _save_known(self._persisted)

    async def _check_bssid(self, ssid: str, bssid: str) -> None:
        if bssid in self._known_bssids:
            self._pending_bssid = None
            self._pending_count = 0
            return
        if self._pending_bssid != bssid:
            self._pending_bssid = bssid
            self._pending_count = 1
            return
        self._pending_count += 1
        if self._pending_count < _BSSID_CONFIRM_COUNT:
            return
        sibling = any(_same_vendor(bssid, known) for known in self._known_bssids)
        self._remember(ssid, bssid)
        self._pending_bssid = None
        self._pending_count = 0
        if sibling:
            # Another band, another SSID slot or a mesh node of the same kit:
            # how every multi-AP home and office looks. Learned, not reported.
            log.info(f"RogueAPDetector: '{ssid}' also served by {bssid} "
                     f"(same hardware family) — learned")
            return
        await self._bus.emit(Event(
            type=EventType.ROGUE_AP,
            level=ThreatLevel.SUSPICIOUS,
            message=f"'{ssid}' is now served by an access point from a "
                    f"different manufacturer ({bssid}) than before — a second "
                    f"router on this network, or an Evil Twin",
            data={"ssid": ssid, "bssid": bssid,
                  "known_bssids": sorted(self._known_bssids - {bssid})},
        ))

    # ── route-hijack exposure ────────────────────────────────────────────

    async def _redirect_loop(self) -> None:
        """Watch redirect acceptance for as long as the module runs.

        Checked repeatedly, not once at startup: these are runtime settings, and
        something turning them back on mid-session is precisely the event worth
        hearing about.
        """
        while True:
            await self._check_redirects()
            await asyncio.sleep(_REDIRECT_POLL)

    async def _check_redirects(self) -> None:
        for family, key, consequence in _REDIRECT_KEYS:
            scopes = await asyncio.to_thread(self._enabled_scopes, family, key)
            token = f"{family}:{key}"
            if not scopes:
                # Turned off again — allow a future change to be reported.
                self._warned_redirects.discard(token)
                continue
            if token in self._warned_redirects:
                continue
            self._warned_redirects.add(token)
            await self._bus.emit(Event(
                type=EventType.ROGUE_AP,
                level=ThreatLevel.SUSPICIOUS,
                message=(f"ICMP redirect acceptance is enabled "
                         f"({', '.join(scopes)}) — {consequence}. "
                         f"Turn it off with: sudo sysctl -w "
                         f"{scopes[0]}=0"),
                data={"interface": self.interface, "family": family,
                      "setting": key, "scopes": scopes,
                      "technique": "icmp_redirect"},
            ))

    def _enabled_scopes(self, family: str, key: str) -> list[str]:
        """The settings that make this interface accept redirects right now.

        Follows the kernel's own rule rather than flagging every scope that
        reads 1. For IPv4 on a host that does not forward, the interface
        accepts redirects if "all" OR its own copy is on (both, when it
        forwards). For IPv6 only the interface's copy counts. "default" is
        just the template for interfaces created later, so on its own it
        exposes nothing — it used to be reported as if it did.
        """
        def on(scope: str, name: str = key) -> bool | None:
            try:
                with open(f"/proc/sys/net/{family}/conf/{scope}/{name}") as f:
                    return f.read().strip() not in ("0", "")
            except Exception:
                return None

        def label(scope: str) -> str:
            return f"net.{family}.conf.{scope}.{key}"

        iface = on(self.interface)
        if family == "ipv6":
            return [label(self.interface)] if iface else []
        every = on("all")
        forwarding = on(self.interface, "forwarding")
        scopes = [label(s) for s, v in (("all", every),
                                        (self.interface, iface)) if v]
        if forwarding:
            return scopes if (every and iface) else []
        return scopes
