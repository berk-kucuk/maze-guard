import asyncio
import re
import subprocess
import threading
import time
from datetime import datetime
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log

_GW_IP_RE  = re.compile(r'default via (\S+)')
_LLADDR_RE = re.compile(r'lladdr\s+([0-9a-f:]{17})')
_INET_RE   = re.compile(r'inet (\d+\.\d+\.\d+\.\d+)/')

# Only re-probe the kernel neighbour cache for a given host this often (s).
# Sniffed ARP is chatty; this bounds `ip neigh` subprocess spawns per host.
_KERNEL_CHECK_COOLDOWN = 5.0


def _kernel_mac(ip: str) -> str | None:
    """MAC the kernel neighbour cache currently maps ``ip`` to, or None.

    Raw sniffed ARP replies are noisy: mesh access points, proxy-ARP and
    dual-homed hosts relay replies bearing *their own* MAC, so a single IP
    legitimately shows up with several source MACs on the wire. The kernel,
    by contrast, only commits a MAC it has actually verified — a genuine ARP
    spoof poisons this cache, transient relay noise does not. We treat it as
    ground truth before ever crying MITM.

    Returns None when the entry is missing or unusable (FAILED/INCOMPLETE),
    which callers read as "no confirmation, stay quiet".
    """
    try:
        out = subprocess.check_output(
            ['ip', 'neigh', 'show', ip], text=True, timeout=3)
    except Exception:
        return None
    if 'FAILED' in out or 'INCOMPLETE' in out:
        return None
    m = _LLADDR_RE.search(out)
    return m.group(1) if m else None


def _get_gateway_info(interface: str | None = None) -> tuple[str | None, str | None]:
    """Return (gateway_ip, gateway_mac) scoped to the given interface.

    Scoping avoids false positives from Docker/VMware virtual adapters that
    introduce their own default routes.
    """
    try:
        cmd = ['ip', 'route', 'show']
        if interface:
            cmd += ['dev', interface]
        route = subprocess.check_output(cmd, text=True, timeout=3)
        m = _GW_IP_RE.search(route)
        if not m:
            return None, None
        gw_ip = m.group(1)
        neigh = subprocess.check_output(
            ['ip', 'neigh', 'show', gw_ip], text=True, timeout=3)
        mac_m = _LLADDR_RE.search(neigh)
        return gw_ip, mac_m.group(1) if mac_m else None
    except Exception:
        return None, None


def _get_own_ips(interface: str) -> set[str]:
    """Return all IPv4 addresses assigned to interface."""
    try:
        out = subprocess.check_output(
            ['ip', 'addr', 'show', interface], text=True, timeout=3)
        return set(_INET_RE.findall(out))
    except Exception:
        return set()


class ARPWatcher:
    def __init__(self, interface: str, whitelist: list[str] | None = None):
        self.interface = interface
        self._whitelist = set(whitelist or [])  # user-configured, permanent
        self._own_ips: set[str] = set()         # dynamic, refreshed every 60 s
        self.devices: dict[str, dict] = {}
        self._arp_table: dict[str, str] = {}   # kernel-confirmed MAC per host
        self._last_check: dict[str, float] = {}  # throttles ip-neigh probes
        self._lock = threading.Lock()          # protects the three dicts above
        self._stop_event = threading.Event()   # signals sniff thread to exit
        self._gw_ip: str | None = None
        self._gw_mac: str | None = None
        self._gw_mac_pending: str | None = None
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._gw_task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus = bus
        self._loop = asyncio.get_event_loop()
        self._stop_event.clear()

        self._own_ips = await asyncio.to_thread(_get_own_ips, self.interface)
        self._gw_ip, self._gw_mac = await asyncio.to_thread(
            _get_gateway_info, self.interface)

        if helper and helper.is_connected():
            helper.on_event(self._on_helper_event)
        else:
            self._task = asyncio.create_task(self._run_direct())
            log.warning("ARPWatcher: helper unavailable, trying direct sniff")
        self._gw_task = asyncio.create_task(self._monitor_gateway())

    async def stop(self) -> None:
        self._stop_event.set()  # wake up scapy's stop_filter
        for t in (self._task, self._gw_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

    async def _on_helper_event(self, msg: dict) -> None:
        if msg.get("event") != "arp":
            return
        ip, mac = msg["src"], msg["mac"]
        if ip in self._whitelist or ip in self._own_ips:
            return
        # _evaluate may shell out to `ip neigh`; keep it off the event loop.
        event = await asyncio.to_thread(self._evaluate, ip, mac)
        if event:
            await self._bus.emit(event)

    async def _run_direct(self) -> None:
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._sniff)
        except Exception as e:
            log.warning(f"ARPWatcher sniff error: {e}")

    def _sniff(self) -> None:
        from scapy.all import ARP, sniff
        sniff(
            iface=self.interface,
            filter="arp",
            prn=lambda p: self._process(p[ARP].psrc, p[ARP].hwsrc)
                          if p.haslayer(ARP) and p[ARP].op == 2 else None,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _process(self, ip: str, mac: str) -> None:
        # Runs on scapy's sniff thread — safe to block on `ip neigh` here.
        if ip in self._whitelist or ip in self._own_ips:
            return
        event = self._evaluate(ip, mac)
        if event:
            asyncio.run_coroutine_threadsafe(self._bus.emit(event), self._loop)

    def _evaluate(self, ip: str, mac: str) -> Event | None:
        """Turn one sniffed ARP reply (ip is-at mac) into an Event, or None.

        Blocking (calls `ip neigh`); never invoke on the event loop directly.
        A raw MAC change on the wire is *not* enough to alert: the reply may
        be relayed by a mesh AP or proxy-ARP router. We only raise ARP_SPOOF
        once the kernel neighbour cache itself has committed a new MAC for the
        host, which is what a real poisoning attack actually causes.
        """
        with self._lock:
            if ip not in self.devices:
                self.devices[ip] = {"mac": mac, "first_seen": datetime.now()}
                self._arp_table[ip] = mac
                return Event(
                    type=EventType.DEVICE_FOUND, level=ThreatLevel.SAFE,
                    message=f"New device: {ip} ({mac})",
                    data={"ip": ip, "mac": mac},
                )
            prev = self._arp_table.get(ip)
            if not prev or prev == mac:
                # Baseline still matches the wire — nothing to corroborate.
                self._arp_table[ip] = mac
                return None
            # Candidate change. Throttle kernel probes so a flapping host
            # can't spawn an `ip neigh` per packet.
            now = time.monotonic()
            if now - self._last_check.get(ip, 0.0) < _KERNEL_CHECK_COOLDOWN:
                return None
            self._last_check[ip] = now

        # Ground-truth check outside the lock (subprocess).
        kmac = _kernel_mac(ip)

        with self._lock:
            prev = self._arp_table.get(ip)
            if not kmac or kmac == prev:
                # Kernel never committed the new MAC → relay/proxy noise.
                # Keep the baseline anchored to the verified value.
                return None
            # The kernel itself moved to a new, verified MAC → real MITM
            # or a genuine device/MAC reassignment. Report kernel truth.
            self._arp_table[ip] = kmac
            if ip in self.devices:
                self.devices[ip]["mac"] = kmac
            return Event(
                type=EventType.ARP_SPOOF, level=ThreatLevel.DANGEROUS,
                message=f"ARP spoofing: {ip} changed MAC from "
                        f"{prev} to {kmac} — possible MITM",
                data={"ip": ip, "old_mac": prev, "new_mac": kmac},
            )

    async def _monitor_gateway(self) -> None:
        """Periodically verify default gateway IP and MAC — early MITM indicator.
        Also refreshes own interface IPs so DHCP changes and network switches
        are picked up within one cycle (replaced, not appended).
        """
        while True:
            await asyncio.sleep(20)
            try:
                # Refresh own IPs — replace set so old-network IPs don't linger
                self._own_ips = await asyncio.to_thread(
                    _get_own_ips, self.interface)
                gw_ip, gw_mac = await asyncio.to_thread(
                    _get_gateway_info, self.interface)
                if not gw_ip:
                    continue
                if self._gw_ip is None:
                    self._gw_ip, self._gw_mac = gw_ip, gw_mac
                    continue
                if gw_ip != self._gw_ip:
                    await self._bus.emit(Event(
                        type=EventType.ARP_SPOOF,
                        level=ThreatLevel.DANGEROUS,
                        message=f"Default gateway changed: {self._gw_ip} → {gw_ip}"
                                f" — possible MITM",
                        data={"ip": gw_ip, "old_ip": self._gw_ip},
                    ))
                    self._gw_ip, self._gw_mac = gw_ip, gw_mac
                elif gw_mac and self._gw_mac and gw_mac != self._gw_mac:
                    # Require the new MAC to persist across two consecutive
                    # cycles — a single STALE/relay blip must not trip MITM.
                    if getattr(self, "_gw_mac_pending", None) != gw_mac:
                        self._gw_mac_pending = gw_mac
                        continue
                    self._gw_mac_pending = None
                    await self._bus.emit(Event(
                        type=EventType.ARP_SPOOF,
                        level=ThreatLevel.DANGEROUS,
                        message=f"Gateway MAC changed: {self._gw_ip} "
                                f"({self._gw_mac} → {gw_mac}) — possible MITM",
                        data={"ip": gw_ip, "old_mac": self._gw_mac, "new_mac": gw_mac},
                    ))
                    self._gw_mac = gw_mac
                else:
                    self._gw_mac_pending = None
            except Exception:
                pass
