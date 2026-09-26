"""
On-demand intelligence about the devices seen on the local network.

The Devices tab lists whatever ARP has told us: an IP, a MAC, when we first
saw it. That answers "something is there", not "what is it". This module runs
the same reconnaissance the engine runs against attackers (maze.utils.recon)
but user-initiated, against a device the user picked from their own network,
and keeps the answer around so re-opening the tab doesn't re-scan.

The cache is deliberately memory-only and short-lived. On a DHCP network an
IP is a lease, not an identity: 192.168.1.42 is a printer this afternoon and
someone's phone tomorrow. Three things therefore invalidate an entry:

  * age            — nothing older than the TTL is shown as current
  * network change — entries are tagged with the network they were gathered
                     on (SSID / gateway MAC); attaching to a different one
                     drops the lot
  * MAC change     — if ARP now reports a different MAC behind that IP, the
                     lease moved and the dossier belongs to another device

Nothing here is written to disk, so quitting the app forgets everything.
"""
import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime

from maze.network.identity import NetworkIdentity
from maze.utils.logger import log

# How long a gathered dossier is considered current. Well under a typical DHCP
# lease, so a stale entry is the exception rather than something to reason
# about — and short enough that "what is open on that box" reflects now.
DEFAULT_TTL = 900.0

# Scans are user-initiated but still real port sweeps; two at a time keeps a
# fast right-click-everything session from turning into a scan of the subnet.
_MAX_CONCURRENT_SCANS = 2


@dataclass
class DeviceIntel:
    """One gathered dossier, plus the context that makes it valid."""
    ip: str
    arp_mac: str = ""            # MAC ARP reported when this was gathered
    network_id: str = ""         # network identity at gather time
    gathered_at: float = field(default_factory=time.monotonic)
    gathered_wall: datetime = field(default_factory=datetime.now)
    result: dict = field(default_factory=dict)
    error: str = ""
    profile: str = "standard"    # scan depth this dossier was built with

    @property
    def age(self) -> float:
        return max(0.0, time.monotonic() - self.gathered_at)

    def remaining(self, ttl: float = DEFAULT_TTL) -> float:
        return max(0.0, ttl - self.age)

    @property
    def risk_score(self) -> int:
        return int(self.result.get("risk_score") or 0)

    @property
    def open_ports(self) -> list:
        return self.result.get("open_ports") or []

    @property
    def name(self) -> str:
        r = self.result
        return (r.get("netbios_name") or r.get("mdns_name")
                or r.get("hostname")
                or (r.get("upnp") or {}).get("friendly_name") or "")

    @property
    def vendor(self) -> str:
        return self.result.get("vendor") or ""

    @property
    def device_kind(self) -> str:
        return self.result.get("device_kind") or ""

    @property
    def model(self) -> str:
        upnp = self.result.get("upnp") or {}
        return " ".join(x for x in (upnp.get("manufacturer", ""),
                                    upnp.get("model_name", "")) if x)

    @property
    def partial(self) -> bool:
        return bool(self.result.get("partial"))


class DeviceIntelCache:
    """Gathers and caches device dossiers for the lifetime of one network.

    Scoping comes from a shared :class:`NetworkIdentity`; one is created if the
    caller has none, but passing the application's own means the cache, the
    inventory and the profile watcher all change networks at the same instant.
    """

    def __init__(self, interface: str = "", ttl: float = DEFAULT_TTL,
                 incidents=None, inventory=None, identity=None):
        self.ttl = ttl
        self._incidents = incidents
        self._inventory = inventory
        self._identity = identity or NetworkIdentity(interface)
        self._identity.on_change(self._on_network_change)
        self._entries: dict[str, DeviceIntel] = {}
        self._inflight: dict[str, asyncio.Task] = {}
        self._progress: dict[str, tuple[str, int, int]] = {}
        self._sem: asyncio.Semaphore | None = None

    # ── network scoping ──────────────────────────────────────────────────

    @property
    def interface(self) -> str:
        return self._identity.interface

    @property
    def network_id(self) -> str:
        return self._identity.network_id

    @property
    def gateway(self) -> str:
        return self._identity.gateway

    def _on_network_change(self, new_id: str, old_id: str) -> None:
        if old_id:
            log.info(f"device intel: network changed ({old_id} → "
                     f"{new_id or '—'}) — dropping cached device info")
            self._entries.clear()

    def set_interface(self, interface: str) -> None:
        self._identity.set_interface(interface)

    async def refresh_network(self) -> str:
        return await self._identity.refresh()

    def start_watcher(self) -> None:
        """Begin (or resume) the shared identity poll. Idempotent; a no-op
        before the event loop is running, so callers retry."""
        self._identity.start()

    def stop_watcher(self) -> None:
        self._identity.stop()

    # ── cache ────────────────────────────────────────────────────────────

    def get(self, ip: str, mac: str = "") -> DeviceIntel | None:
        """The current dossier for ``ip``, or None if there is none, it has
        expired, or it no longer describes the device now behind that IP."""
        intel = self._entries.get(ip)
        if intel is None:
            return None
        if intel.age > self.ttl:
            self._entries.pop(ip, None)
            return None
        if (self.network_id and intel.network_id
                and intel.network_id != self.network_id):
            self._entries.pop(ip, None)
            return None
        if mac and intel.arp_mac and mac.lower() != intel.arp_mac.lower():
            # Same address, different hardware: the lease moved on.
            self._entries.pop(ip, None)
            return None
        return intel

    def prune(self) -> int:
        """Drop everything expired. Returns how many entries went."""
        stale = [ip for ip, i in self._entries.items() if i.age > self.ttl]
        for ip in stale:
            self._entries.pop(ip, None)
        return len(stale)

    def forget(self, ip: str) -> None:
        self._entries.pop(ip, None)

    def clear(self) -> None:
        self._entries.clear()

    def is_scanning(self, ip: str) -> bool:
        task = self._inflight.get(ip)
        return task is not None and not task.done()

    def scanning(self) -> set[str]:
        return {ip for ip, t in self._inflight.items() if not t.done()}

    def progress(self, ip: str) -> tuple[str, int, int] | None:
        """(stage, done, total) for a scan in flight, or None."""
        return self._progress.get(ip)

    # ── gathering ────────────────────────────────────────────────────────

    async def gather(self, ip: str, mac: str = "", force: bool = False,
                     profile: str = "standard") -> DeviceIntel:
        """Gather (or return cached) intelligence for ``ip``.

        Concurrent calls for the same IP share one scan rather than starting a
        second sweep against the same host. A cached dossier from a shallower
        profile does not satisfy a request for a deeper one.
        """
        if not force:
            cached = self.get(ip, mac)
            if cached is not None and not _deeper(profile, cached.profile):
                return cached
        running = self._inflight.get(ip)
        if running is not None and not running.done():
            return await asyncio.shield(running)

        task = asyncio.ensure_future(self._gather(ip, mac, profile))
        self._inflight[ip] = task
        try:
            return await task
        finally:
            if self._inflight.get(ip) is task:
                self._inflight.pop(ip, None)
            self._progress.pop(ip, None)

    async def _gather(self, ip: str, mac: str,
                      profile: str = "standard") -> DeviceIntel:
        from maze.utils.recon import recon_ip
        from maze.protection.dns_leak import _is_private_ip

        # Same guard the engine applies: only probe on-link, private addresses.
        # The Devices tab is built from ARP, so everything in it should already
        # qualify — but the address ultimately comes off the wire, and a public
        # one here would mean port-scanning an uninvolved third party.
        if not _is_private_ip(ip):
            return DeviceIntel(ip=ip, arp_mac=mac,
                               network_id=self.network_id, error="not_local")

        await self.refresh_network()

        def on_progress(stage: str, done: int, total: int) -> None:
            self._progress[ip] = (stage, done, total)

        if self._sem is None:
            self._sem = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)
        self._progress[ip] = ("queued", 0, 0)
        async with self._sem:
            try:
                result = await recon_ip(ip, profile=profile,
                                        on_progress=on_progress)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(f"device intel scan of {ip} failed: {exc}")
                return DeviceIntel(ip=ip, arp_mac=mac, profile=profile,
                                   network_id=self.network_id, error=str(exc))

        data = result.to_dict()
        # The router is the one device we never have to guess at: it is
        # whatever the routing table says it is. A port-shape heuristic that
        # disagrees with the kernel is simply wrong.
        if ip and ip == self.gateway:
            data["device_kind"] = "Router / gateway"
            data["is_gateway"] = True
        intel = DeviceIntel(
            ip=ip,
            arp_mac=mac or result.mac,
            network_id=self.network_id,
            result=data,
            profile=profile,
        )
        self._entries[ip] = intel

        # If this device already has a dossier as an attacker, enrich it. We
        # never *create* one here: scanning a device from the Devices tab is a
        # question about a neighbour, not an accusation against it.
        try:
            if self._incidents is not None and self._incidents.get(ip):
                self._incidents.attach_recon(ip, data)
        except Exception as exc:
            log.debug(f"device intel: could not enrich incident {ip}: {exc}")

        # What a scan learns about a device outlives the scan's cache: the
        # inventory is keyed by MAC, so the name and model survive the lease.
        try:
            if self._inventory is not None and intel.arp_mac:
                self._inventory.enrich(
                    intel.arp_mac, self.network_id, vendor=intel.vendor,
                    kind=intel.device_kind, name=intel.name)
        except Exception as exc:
            log.debug(f"device intel: could not enrich inventory {ip}: {exc}")

        return intel


_DEPTH = {"quick": 0, "standard": 1, "thorough": 2}


def _deeper(wanted: str, have: str) -> bool:
    return _DEPTH.get(wanted, 1) > _DEPTH.get(have, 1)


# ── formatting ───────────────────────────────────────────────────────────────

def export_markdown(intel: DeviceIntel) -> str:
    """A device report that can be filed, mailed or attached to a ticket.

    Deliberately English and translation-free: unlike the on-screen pane, this
    leaves the machine it was written on.
    """
    r = intel.result
    upnp = r.get("upnp") or {}
    lines = [
        f"# Maze Guard device report — {intel.ip}",
        "",
        f"Generated:   {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Gathered:    {intel.gathered_wall:%Y-%m-%d %H:%M:%S} "
        f"({_fmt_age(intel.age)} earlier)",
        f"Scan depth:  {intel.profile} "
        f"({r.get('ports_scanned', 0)} ports, {r.get('duration_s', 0)}s)"
        + ("  — INCOMPLETE, time budget reached" if intel.partial else ""),
        "",
        "## Identity",
        f"- IP address:   {intel.ip}",
        f"- MAC:          {r.get('mac') or intel.arp_mac or 'unknown'}"
        + (f"  ({r['vendor']})" if r.get("vendor") else "")
        + ("  [randomised]" if r.get("randomized_mac") else ""),
        f"- Name:         {intel.name or 'unknown'}",
        f"- Device type:  {intel.device_kind or 'unclassified'}",
        f"- Model:        {intel.model or 'unknown'}",
        f"- OS guess:     {r.get('os_hint') or 'unknown'}",
        f"- Latency:      {r.get('latency_ms') or '—'} ms",
        f"- Risk score:   {intel.risk_score}/100",
    ]
    if upnp.get("model_description"):
        lines.append(f"- Description:  {upnp['model_description']}")

    ports = r.get("open_ports") or []
    lines += ["", f"## Open ports ({len(ports)})"]
    if ports:
        banners = r.get("banners") or {}
        titles = r.get("http_titles") or {}
        for entry in ports:
            port, name = (entry if isinstance(entry, (list, tuple))
                          else (entry, "?"))
            extra = banners.get(str(port)) or titles.get(str(port)) or ""
            lines.append(f"- {port}/{name}" + (f" — {extra}" if extra else ""))
    else:
        lines.append("- none found")

    if r.get("tls_info"):
        lines += ["", "## TLS certificates"]
        for port, info in r["tls_info"].items():
            lines.append(
                f"- port {port}: CN={info.get('subject_cn') or info.get('subject') or '?'}"
                + ("  [self-signed]" if info.get("self_signed") else "")
                + (f"  {info.get('tls_version', '')}"))

    lines += ["", "## Findings"]
    lines += ([f"- {f}" for f in r["findings"]] if r.get("findings")
              else ["- nothing of note"])
    lines += ["", "---", "",
              "Gathered on request from the Maze Guard Devices tab. Scope: one "
              "on-link host on the operator's own network.", ""]
    return "\n".join(lines)


def _fmt_age(seconds: float) -> str:
    secs = int(seconds)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    return f"{secs // 3600}h"


def summarize_intel(intel: DeviceIntel, t=lambda k: k) -> str:
    """One-cell summary for the device table."""
    if intel.error:
        return t("dev_failed")
    parts = [f"{len(intel.open_ports)} {t('dev_ports')}"]
    if intel.risk_score:
        parts.append(f"{t('dev_risk')} {intel.risk_score}")
    if intel.partial:
        parts.append(t("dev_partial_short"))
    return " · ".join(parts)


def describe_progress(progress: tuple[str, int, int] | None,
                      t=lambda k: k) -> str:
    """Turn a recon progress tick into something worth reading."""
    if not progress:
        return t("dev_scanning")
    stage, done, total = progress
    if stage == "ports" and total:
        return f"{t('dev_stage_ports')} {done}/{total}"
    return t({
        "queued":   "dev_stage_queued",
        "identity": "dev_stage_identity",
        "services": "dev_stage_services",
        "done":     "dev_stage_done",
    }.get(stage, "dev_scanning"))


def format_intel(intel: DeviceIntel, t=lambda k: k,
                 ttl: float = DEFAULT_TTL) -> str:
    """Full report for the detail pane."""
    if intel.error == "not_local":
        return t("dev_not_local")
    if intel.error:
        return f"{t('dev_failed')}: {intel.error}"

    r = intel.result
    # Labels are translated, so their width is not knowable up front: collect
    # the rows first and align them to the longest label that ends up used.
    pending: list[list] = []

    def row(label: str, value: str) -> str:
        marker = f"\x00{len(pending)}\x00"
        pending.append([label, value])
        return marker

    lines = [
        f"{t('dev_gathered')}: {intel.gathered_wall:%H:%M:%S}"
        f"  ({_fmt_age(intel.age)} {t('dev_ago')} · "
        f"{t('dev_expires_in')} {_fmt_age(intel.remaining(ttl))})",
        "",
        f"── {t('threats_identity')} ──",
        row("IP", intel.ip),
    ]
    mac = r.get("mac") or intel.arp_mac
    if mac:
        value = mac
        if r.get("vendor"):
            value += f"  ({r['vendor']})"
        if r.get("randomized_mac"):
            value += f"  [{t('dev_random_mac')}]"
        lines.append(row("MAC", value))
    lines.append(row(t("dev_name"), intel.name or "—"))
    if intel.device_kind:
        lines.append(row(t("dev_kind"), intel.device_kind))
    if intel.model:
        lines.append(row(t("dev_model"), intel.model))
    upnp = r.get("upnp") or {}
    if upnp.get("model_description"):
        lines.append(row(t("dev_description"), upnp["model_description"]))
    lines.append(row("OS", r.get("os_hint") or "—"))
    if r.get("latency_ms"):
        lines.append(row("RTT", f"{r['latency_ms']} ms"))
    if r.get("risk_score"):
        lines.append(row(t("dev_risk"), f"{r['risk_score']}/100"))
    lines.append(row(t("dev_scan_profile"),
                     f"{t('dev_profile_' + intel.profile)}"
                     f"  ({r.get('ports_scanned', 0)} {t('dev_ports')}, "
                     f"{r.get('duration_s', 0)}s)"))
    if intel.partial:
        lines.append(f"  ! {t('dev_partial')}")

    ports = r.get("open_ports") or []
    lines += ["", f"── {t('dev_open_ports')} ({len(ports)}) ──"]
    if ports:
        banners = r.get("banners") or {}
        titles = r.get("http_titles") or {}
        for entry in ports:
            port, name = (entry if isinstance(entry, (list, tuple))
                          else (entry, "?"))
            extra = banners.get(str(port)) or titles.get(str(port)) or ""
            lines.append(f"  {port:>6}/{name}" + (f"   {extra}" if extra else ""))
    else:
        lines.append(f"  {t('dev_no_open_ports')}")

    tls = r.get("tls_info") or {}
    if tls:
        lines += ["", "── TLS ──"]
        for port, info in tls.items():
            cn = info.get("subject_cn") or info.get("subject") or "?"
            lines.append(f"  {port}: CN={cn}"
                         + ("  [self-signed]" if info.get("self_signed") else "")
                         + (f"  {info.get('tls_version', '')}"))

    if r.get("findings"):
        lines += ["", f"── {t('threats_findings')} ──"]
        for f in r["findings"]:
            lines.append(f"  ! {f}")

    width = max((len(label) for label, _ in pending), default=0) + 2
    text = "\n".join(lines)
    for i, (label, value) in enumerate(pending):
        text = text.replace(f"\x00{i}\x00", f"{label + ':':<{width}}{value}")
    return text
