import asyncio
import re
import socket
import struct
import subprocess
import time
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import FAIL, PASS, Verdict, WARN, merge
from maze.utils.ipaddr import is_private
from maze.utils.logger import log

_IPV4_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# TEST-NET-2 (RFC 5737): reserved for documentation, routed nowhere, and
# certainly not anybody's configured resolver — which is exactly what the
# self-test needs to push through the rule without inventing a real one.
_PROBE_RESOLVER = "198.51.100.53"


def _is_private_ip(ip: str) -> bool:
    """True for anything that can only exist on a local network.

    Kept as a module-level name because half the application imports it from
    here; the implementation lives in maze.utils.ipaddr, which answers for IPv6
    as well — the prefix-matching version this replaced treated every IPv6
    address, including an attacker's link-local one, as remote.
    """
    return is_private(ip)


def _get_configured_dns_servers() -> set[str]:
    """Read nameserver entries from /etc/resolv.conf (IPv4 only).

    On systemd-resolved systems this returns {'127.0.0.53'}, which is
    the stub listener — correct for leak detection purposes since all
    app-level DNS goes there.
    """
    servers: set[str] = set()
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2 and ":" not in parts[1]:  # skip IPv6
                        servers.add(parts[1])
    except Exception:
        pass
    return servers


def _get_resolved_upstreams() -> set[str]:
    """Real upstream DNS servers configured in systemd-resolved (IPv4 only).

    On systemd-resolved systems /etc/resolv.conf only lists the 127.0.0.53
    stub; the actual upstreams the user (or DHCP) configured live inside
    resolved. Without consulting them, every query resolved forwards to its
    legitimate upstream (e.g. 1.1.1.1 / 1.0.0.1) looks like a DNS hijack.
    """
    servers: set[str] = set()
    try:
        out = subprocess.check_output(
            ["resolvectl", "dns"], text=True, timeout=2,
            stderr=subprocess.DEVNULL,
        )
        for ip in _IPV4_RE.findall(out):
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                servers.add(ip)
    except Exception:
        pass
    return servers


def _get_resolved_fallback() -> set[str]:
    """DNS servers systemd-resolved may legitimately use beyond the per-link
    upstreams: the global 'Current DNS Server' and the built-in 'Fallback DNS
    Servers' (IPv4 only).

    When no per-link/global DNS is configured (e.g. DHCP handed over none),
    resolved falls back to its compiled-in public resolvers — by default
    Quad9 (9.9.9.9), Cloudflare (1.1.1.1) and Google (8.8.8.8). Those queries
    genuinely egress to those IPs and are NOT a hijack, so they must count as
    expected. 'resolvectl dns' never lists them, only 'resolvectl status' does.
    """
    servers: set[str] = set()
    try:
        out = subprocess.check_output(
            ["resolvectl", "status", "--no-pager"], text=True, timeout=2,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return servers
    # Both the 'Fallback DNS Servers:' block (with indented continuation lines)
    # and the 'Current DNS Server:' line hold legitimate resolvers. No other
    # IPv4 addresses appear in this output, so extracting them all is safe.
    for ip in _IPV4_RE.findall(out):
        if all(0 <= int(o) <= 255 for o in ip.split(".")):
            servers.add(ip)
    return servers


def _get_nm_dns_servers() -> set[str]:
    """DNS servers reported by NetworkManager (IPv4 only).

    Covers setups where resolvectl has no per-link DNS because NetworkManager
    manages DNS internally (e.g. dns=default in NetworkManager.conf).
    """
    servers: set[str] = set()
    try:
        out = subprocess.check_output(
            ["nmcli", "--terse", "--fields", "IP4.DNS", "dev", "show"],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        )
        for ip in _IPV4_RE.findall(out):
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                servers.add(ip)
    except Exception:
        pass
    return servers


def _get_active_vpn_interfaces() -> list[str]:
    from maze.utils.network_info import get_active_vpn_interfaces
    return get_active_vpn_interfaces()


def _dns_egress_iface(ip: str) -> str | None:
    """Interface a packet to ``ip`` would actually leave through.

    /proc/net/udp exposes the DNS *destination* but not the egress path. The
    routing table does: under a full-tunnel VPN, even public resolvers such as
    9.9.9.9 route out via tun0, so they are NOT leaks. Returns None when the
    egress interface can't be determined.
    """
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", ip], text=True, timeout=2,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None
    m = re.search(r'\bdev\s+(\S+)', out)
    return m.group(1) if m else None


def _read_udp_dns_destinations() -> list[str]:
    """Return destination IPs of active UDP port-53 sockets (IPv4 only).

    Reads only /proc/net/udp — /proc/net/udp6 uses 32-char IPv6 hex which
    requires different decoding and is rarely relevant for DNS leak detection.
    """
    destinations: list[str] = []
    try:
        with open("/proc/net/udp") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            rem = parts[2]
            if ":" not in rem:
                continue
            rem_ip_hex, rem_port_hex = rem.rsplit(":", 1)
            if len(rem_ip_hex) != 8:
                continue
            if int(rem_port_hex, 16) != 53:
                continue
            ip = socket.inet_ntoa(struct.pack("<I", int(rem_ip_hex, 16)))
            if ip != "0.0.0.0":
                destinations.append(ip)
    except Exception:
        pass
    return destinations


class DNSLeakPreventer:
    """
    Detect plaintext DNS traffic escaping the resolver it is supposed to use.

    Two sources feed the same judgement:

    * **Live capture** (when the privileged helper is connected). Every UDP/53
      packet leaving this host is examined as it happens. This is what makes
      the module work at all for ordinary applications: a DNS query and its
      answer are over in milliseconds, so the socket that carried them is gone
      long before any poll comes round. Polling could only ever catch the
      long-lived socket systemd-resolved keeps to its upstream — which is why
      a browser resolving names on its own used to sail past unnoticed.
    * **/proc/net/udp poll** every 60 s, kept as the fallback for when the
      helper is unavailable, and as a backstop for sockets held open.

    The verdict itself is unchanged:

    Without VPN: warn only if DNS goes to a public address that appears in
    neither /etc/resolv.conf nor the resolver daemon's own upstream list — a
    real hijack points you at a resolver you never configured. Private
    addresses are never flagged without a VPN, since the home router is normal.

    With VPN active: a query is a leak only if it actually egresses through a
    non-VPN interface, checked against the routing table. Queries that route
    through the tunnel — including ones to public resolvers such as 9.9.9.9 —
    are legitimate under a full tunnel and are not flagged.
    """

    # How long a resolver-configuration snapshot is reused. Reading it costs
    # three subprocesses, and a per-packet check cannot afford that; the
    # configuration itself changes on the timescale of a network switch.
    _CONFIG_TTL = 30.0
    # Don't re-judge the same destination more often than this.
    _JUDGE_TTL = 30.0
    # Don't repeat a warning about one address inside this window.
    _WARN_TTL = 1800.0

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._bus = None
        self._helper = None
        self._warned: dict[str, float] = {}       # ip -> timestamp
        self._judged: dict[str, float] = {}       # ip -> timestamp
        self._last_vpn_state: frozenset[str] = frozenset()
        self._config: tuple | None = None         # cached resolver picture
        self._config_at: float = 0.0
        self._live = False                        # capture feed available
        self._queries = 0                         # observed outbound queries

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, bus, helper=None) -> None:
        self._bus = bus
        self._helper = helper
        self._live = bool(helper and helper.is_connected())
        if self._live:
            helper.on_event(self._on_helper_event)
        else:
            log.warning("DNSLeakPreventer: helper unavailable — falling back "
                        "to /proc polling, which only sees long-lived sockets")
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._helper is not None:
            self._helper.off_event(self._on_helper_event)
        if self._task:
            self._task.cancel()
        self._task = None

    # ── what the interface shows ─────────────────────────────────────────

    def status_detail(self) -> str:
        if not self._live:
            return ("no packet capture — only DNS sockets held open long "
                    "enough to be polled are seen")
        if not self._queries:
            return "watching outbound DNS live; none seen yet"
        return f"watching outbound DNS live; {self._queries} queries examined"

    # ── self-test ────────────────────────────────────────────────────────

    async def verify(self) -> Verdict:
        """Prove the rule fires, and say whether anything is feeding it."""
        rule = await asyncio.to_thread(self._verify_rule)
        feed = self._verify_feed()
        return merge(rule, feed)

    def _verify_rule(self) -> Verdict:
        """Run a fabricated unconfigured resolver through the real judgement."""
        configured, upstreams, vpn = self._resolver_picture()
        picture = [
            f"resolv.conf: {', '.join(sorted(configured)) or 'none'}",
            f"resolver daemon upstreams: "
            f"{', '.join(sorted(upstreams)) or 'none'}",
            f"VPN: {', '.join(vpn) if vpn else 'not active'}",
        ]
        verdict = self._judge(_PROBE_RESOLVER)
        if verdict:
            return Verdict(PASS,
                           f"the rule fires: a query to an unconfigured "
                           f"resolver ({_PROBE_RESOLVER}) is judged a leak",
                           picture + [verdict])
        if vpn:
            # Under a full tunnel this is the right answer, not a failure: the
            # query would leave through the VPN, which is where it belongs.
            return Verdict(PASS,
                           f"the rule fires: a query to {_PROBE_RESOLVER} "
                           f"would route through the tunnel, so it is correctly "
                           f"not a leak — a query leaving around the tunnel "
                           f"would be", picture)
        return Verdict(FAIL,
                       f"the rule did NOT flag a query to {_PROBE_RESOLVER}, "
                       f"an address that is in no resolver configuration on "
                       f"this machine — leak detection is not working",
                       picture)

    def _verify_feed(self) -> Verdict:
        if not self._live:
            return Verdict(WARN,
                           "no packet capture: only DNS sockets still open when "
                           "the 60-second poll comes round can be seen, which "
                           "an application's own query never is")
        if not self._queries:
            return Verdict(WARN,
                           "live capture is attached but no DNS query has been "
                           "observed yet — resolve a name and test again")
        return Verdict(PASS,
                       f"live capture is attached: {self._queries} outbound DNS "
                       f"queries examined as they left this machine")

    # ── live capture feed ────────────────────────────────────────────────

    async def _on_helper_event(self, msg: dict) -> None:
        if msg.get("event") != "dns":
            return
        # Only queries leaving this host, and only ones addressed to a resolver
        # (destination port 53). An answer coming back tells us nothing the
        # question did not.
        if not msg.get("outbound") or int(msg.get("dport", 0)) != 53:
            return
        ip = msg.get("dst", "")
        if not ip:
            return
        self._queries += 1
        now = time.monotonic()
        if now - self._judged.get(ip, -self._JUDGE_TTL) < self._JUDGE_TTL:
            return
        self._judged[ip] = now
        try:
            verdict = await asyncio.to_thread(self._judge, ip)
        except Exception as exc:
            log.debug(f"DNSLeakPreventer: could not judge {ip}: {exc}")
            return
        if verdict:
            await self._report(ip, verdict)

    # ── polling fallback ─────────────────────────────────────────────────

    async def _monitor(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                leaks = await asyncio.to_thread(self._find_leaks)
                for ip, msg in leaks:
                    await self._report(ip, msg)
            except Exception as exc:
                log.warning(f"DNSLeakPreventer check error: {exc}")

    def _find_leaks(self) -> list[tuple[str, str]]:
        leaks: list[tuple[str, str]] = []
        for ip in _read_udp_dns_destinations():
            verdict = self._judge(ip)
            if verdict:
                leaks.append((ip, verdict))
        return leaks

    # ── judgement ────────────────────────────────────────────────────────

    async def _report(self, ip: str, message: str) -> None:
        now = time.monotonic()
        if now - self._warned.get(ip, -self._WARN_TTL) < self._WARN_TTL:
            return
        self._warned[ip] = now
        await self._bus.emit(Event(
            type=EventType.DNS_LEAK,
            level=ThreatLevel.SUSPICIOUS,
            message=message,
            data={"ip": ip},
        ))

    def _resolver_picture(self) -> tuple[set[str], set[str], list[str]]:
        """(resolv.conf servers, daemon upstreams, VPN interfaces), cached.

        Blocking — call from a thread. A VPN coming up or going down clears the
        warned set, so a reconnect can surface leaks the previous session had
        already reported and fallen silent about.
        """
        now = time.monotonic()
        if self._config is not None and now - self._config_at < self._CONFIG_TTL:
            return self._config

        configured = _get_configured_dns_servers()
        upstreams = (_get_resolved_upstreams()
                     | _get_resolved_fallback()
                     | _get_nm_dns_servers())
        vpn_ifaces = _get_active_vpn_interfaces()

        vpn_state = frozenset(vpn_ifaces)
        if vpn_state != self._last_vpn_state:
            self._warned.clear()
            self._judged.clear()
            self._last_vpn_state = vpn_state

        self._config = (configured, upstreams, vpn_ifaces)
        self._config_at = now
        return self._config

    def _judge(self, ip: str) -> str | None:
        """Why ``ip`` is a leak, or None if this query is expected.

        Blocking (reads the routing table) — call from a thread.
        """
        configured, upstreams, vpn_ifaces = self._resolver_picture()

        if ip in configured:
            return None                     # goes to the expected resolver

        if vpn_ifaces:
            # A DNS query is a leak only if it actually leaves via a non-VPN
            # interface. The destination alone does not tell us that — a full
            # tunnel routes even public resolvers (9.9.9.9, 1.1.1.1) out
            # through itself, which is fine. Ask the routing table.
            egress = _dns_egress_iface(ip)
            if egress is None or egress in set(vpn_ifaces):
                return None
            return (f"DNS leak detected: query to {ip} egresses via "
                    f"'{egress}' instead of the VPN tunnel "
                    f"({', '.join(vpn_ifaces)})")

        # No VPN: private addresses are your LAN/router DNS — normal — and the
        # resolver daemon's configured upstreams (which never appear in
        # resolv.conf, only the 127.0.0.53 stub does) are legitimate too. Flag
        # only public addresses matching neither.
        if not _is_private_ip(ip) and ip not in upstreams:
            return (f"Unexpected DNS server: query to {ip} "
                    f"(not in resolv.conf) — possible DNS hijack")
        return None
