import asyncio
import re
import socket
import struct
import subprocess
import time
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log

_IPV4_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _is_private_ip(ip: str) -> bool:
    """True for RFC 1918, loopback, link-local, and unspecified addresses."""
    if ip in ("0.0.0.0", "255.255.255.255"):
        return True
    if ip.startswith("127.") or ip.startswith("169.254."):
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    try:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172":
            second = int(parts[1])
            if 16 <= second <= 31:
                return True
    except (ValueError, IndexError):
        pass
    return False


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
    Detects plaintext DNS traffic leaking outside the expected resolver.

    Without VPN: warns only if DNS goes to a public IP not listed in
    /etc/resolv.conf (possible DNS hijack). Private IPs are never flagged
    without VPN since the home router DNS is normal.

    With VPN active: a DNS query is only a leak if it actually egresses via a
    non-VPN interface (checked against the routing table). Queries that route
    through the tunnel — including ones to public resolvers like 9.9.9.9 — are
    legitimate under a full-tunnel VPN and are not flagged.

    VPN state changes reset the warned-IPs set so a reconnect can surface
    new leaks that weren't present in the previous session.
    """

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._bus = None
        self._warned: dict[str, float] = {}  # ip -> timestamp
        self._last_vpn_state: frozenset[str] = frozenset()

    async def start(self, bus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _monitor(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                leaks = await asyncio.to_thread(self._find_leaks)
                for ip, msg in leaks:
                    now = time.monotonic()
                    if ip not in self._warned or now - self._warned[ip] > 1800:
                        self._warned[ip] = now
                        await self._bus.emit(Event(
                            type=EventType.DNS_LEAK,
                            level=ThreatLevel.SUSPICIOUS,
                            message=msg,
                            data={"ip": ip},
                        ))
            except Exception as exc:
                log.warning(f"DNSLeakPreventer check error: {exc}")

    def _find_leaks(self) -> list[tuple[str, str]]:
        leaks: list[tuple[str, str]] = []
        destinations = _read_udp_dns_destinations()
        if not destinations:
            return leaks

        configured = _get_configured_dns_servers()
        resolved_upstreams = (
            _get_resolved_upstreams()
            | _get_resolved_fallback()
            | _get_nm_dns_servers()
        )
        vpn_ifaces = _get_active_vpn_interfaces()
        vpn_state = frozenset(vpn_ifaces)

        # VPN state changed (connected / disconnected / switched server):
        # clear warned set so new leaks surface immediately.
        if vpn_state != self._last_vpn_state:
            self._warned.clear()
            self._last_vpn_state = vpn_state

        vpn_active = bool(vpn_ifaces)
        vpn_set = set(vpn_ifaces)

        for ip in destinations:
            if ip in configured:
                continue  # goes to expected resolver

            if vpn_active:
                # A DNS query is a leak only if it actually leaves via a
                # non-VPN interface. The destination alone doesn't tell us that
                # — a full-tunnel VPN routes even public resolvers (9.9.9.9,
                # 1.1.1.1) out through the tunnel, which is fine. Consult the
                # routing table for the real egress path.
                egress = _dns_egress_iface(ip)
                if egress is None or egress in vpn_set:
                    continue  # routed through the tunnel (or unknown) → not a leak
                msg = (
                    f"DNS leak detected: query to {ip} egresses via '{egress}' "
                    f"instead of the VPN tunnel ({', '.join(vpn_ifaces)})"
                )
                leaks.append((ip, msg))
            else:
                # No VPN: private IPs are your LAN/router DNS — normal, and
                # systemd-resolved's configured upstreams (which never appear
                # in resolv.conf, only the 127.0.0.53 stub does) are legit too.
                # Flag only public IPs that match neither — a real hijack
                # redirects you to a resolver you never configured.
                if not _is_private_ip(ip) and ip not in resolved_upstreams:
                    msg = (
                        f"Unexpected DNS server: query to {ip} "
                        f"(not in resolv.conf) — possible DNS hijack"
                    )
                    leaks.append((ip, msg))

        return leaks
