import asyncio
import re
import subprocess
import threading
import time
from datetime import datetime
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import (FAIL, PASS, Verdict, WARN,
                              capture_feed, merge)
from maze.utils.logger import log
from maze.utils.network_info import link_epoch

_GW_IP_RE  = re.compile(r'default via (\S+)')
_LLADDR_RE = re.compile(r'lladdr\s+([0-9a-f:]{17})')
_INET_RE   = re.compile(r'inet (\d+\.\d+\.\d+\.\d+)/')
# IPv6 addresses are ours too. Without them, our own v6 traffic looked
# like an unknown host on the segment to every detector downstream.
_INET6_RE  = re.compile(r'inet6 ([0-9a-fA-F:]+)/')

# Only re-probe the kernel neighbour cache for a given host this often (s).
# Sniffed ARP is chatty; this bounds `ip neigh` subprocess spawns per host.
_KERNEL_CHECK_COOLDOWN = 5.0
# How recently the PREVIOUS owner of an address must have been heard for a
# MAC change to count as a conflict. On a public network addresses move all
# the time for an innocent reason — a phone leaves, its DHCP lease lapses, the
# next arrival gets the same IP — and the old device has been silent for
# minutes by then. Real ARP poisoning is the opposite: the legitimate host is
# still there, still answering, and two MACs fight over one IP within seconds.
_OLD_MAC_ALIVE_WINDOW = 60.0


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
        cmd = ['ip', 'neigh', 'show', gw_ip]
        if interface:
            cmd += ['dev', interface]
        neigh = subprocess.check_output(cmd, text=True, timeout=3)
        if 'FAILED' in neigh or 'INCOMPLETE' in neigh:
            return gw_ip, None
        mac_m = _LLADDR_RE.search(neigh)
        return gw_ip, mac_m.group(1) if mac_m else None
    except Exception:
        return None, None


def _get_own_ips(interface: str) -> set[str]:
    """Return every address on this HOST — both families, not just ``interface``'s.

    Callers use this as the "traffic we generated ourselves" filter, so scoping
    it to one interface produced constant false positives:

    * Starting a VM brings up libvirt/QEMU interfaces (virbr0 at 192.168.122.1,
      vnet*/tap*). Those addresses are ours, but they were absent from the set,
      so the guest and the bridge looked like unknown hosts appearing on the
      network — an alert every time a VM booted.
    * Running a local port sweep (nmap) emits SYNs whose source is this machine.
      If they left via any interface other than the monitored one — or if the
      monitored interface name was stale, in which case `ip addr show <iface>`
      fails and this returned an EMPTY set, filtering nothing at all — our own
      scan was reported as an incoming attack.

    ``interface`` is kept in the signature for call-site compatibility; the
    host-wide answer is strictly safer, since an address that is genuinely ours
    must never be attributed to an attacker.
    """
    own: set[str] = set()
    for flag, pattern in (('-4', _INET_RE), ('-6', _INET6_RE)):
        try:
            out = subprocess.check_output(
                ['ip', flag, 'addr', 'show'], text=True, timeout=3)
            own |= set(pattern.findall(out))
        except Exception:
            continue
    return own


class ARPWatcher:
    def __init__(self, interface: str, whitelist: list[str] | None = None):
        self.interface = interface
        self._whitelist = set(whitelist or [])  # user-configured, permanent
        self._own_ips: set[str] = set()         # dynamic, refreshed every 60 s
        self.devices: dict[str, dict] = {}
        self._arp_table: dict[str, str] = {}   # kernel-confirmed MAC per host
        self._last_check: dict[str, float] = {}  # throttles ip-neigh probes
        self._mac_seen: dict[str, float] = {}    # mac → last ARP heard (monotonic)
        self._lock = threading.Lock()          # protects the three dicts above
        self._stop_event = threading.Event()   # signals sniff thread to exit
        self._gw_ip: str | None = None
        self._gw_mac: str | None = None
        self._gw_mac_pending: str | None = None
        self._gw_ip_pending: str | None = None
        self._bus: EventBus | None = None
        self._helper = None
        self._task: asyncio.Task | None = None
        self._gw_task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._epoch: tuple | None = None   # see network_info.link_epoch
        self._capture = ""      # "helper" | "direct" — where packets come from
        self._seen = 0          # ARP packets accepted, for the self-test

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus = bus
        self._loop = asyncio.get_event_loop()
        self._stop_event.clear()

        self._own_ips = await asyncio.to_thread(_get_own_ips, self.interface)
        self._gw_ip, self._gw_mac = await asyncio.to_thread(
            _get_gateway_info, self.interface)
        self._epoch = await asyncio.to_thread(link_epoch, self.interface)

        self._helper = helper
        if helper and helper.is_connected():
            self._capture = "helper"
            helper.on_event(self._on_helper_event)
        else:
            self._capture = "direct"
            self._task = asyncio.create_task(self._run_direct())
            log.warning("ARPWatcher: helper unavailable, trying direct sniff")
        self._gw_task = asyncio.create_task(self._monitor_gateway())

    async def stop(self) -> None:
        self._stop_event.set()  # wake up scapy's stop_filter
        if self._helper is not None:
            self._helper.off_event(self._on_helper_event)
        for t in (self._task, self._gw_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

    def network_changed(self) -> None:
        """Forget everything learned about the previous network.

        Called when the link is re-established (new cable, new WiFi
        association). Without it the old network's gateway and hosts stayed
        the baseline, and simply walking from home WiFi to the office one
        raised "Gateway MAC changed — possible MITM".
        """
        with self._lock:
            self.devices.clear()
            self._arp_table.clear()
            self._last_check.clear()
            self._mac_seen.clear()
        self._gw_ip = self._gw_mac = None
        self._gw_ip_pending = self._gw_mac_pending = None

    def status_detail(self) -> str:
        if self._capture == "direct":
            return ("capturing directly — needs root; without it no ARP is "
                    "seen and only the gateway is watched")
        gw = f"gateway {self._gw_ip} at {self._gw_mac}" if self._gw_mac else \
             "no gateway MAC yet"
        return f"{len(self.devices)} devices seen · {gw}"

    async def verify(self) -> Verdict:
        """Check the two things this detector cannot work without.

        The gateway is the anchor: without its address and MAC there is nothing
        to notice a change *from*, so the module can be running perfectly and
        still be incapable of reporting the attack it exists for.
        """
        gw_ip, gw_mac = await asyncio.to_thread(
            _get_gateway_info, self.interface)
        if not gw_ip:
            anchor = Verdict(FAIL,
                             "no default gateway on this interface — there is "
                             "no baseline for MITM detection to compare against",
                             [f"interface: {self.interface}"])
        elif not gw_mac:
            anchor = Verdict(WARN,
                             f"the gateway {gw_ip} is known but its MAC has not "
                             f"been resolved yet, so a MAC swap cannot be seen",
                             [])
        else:
            anchor = Verdict(PASS,
                             f"the gateway is pinned: {gw_ip} at {gw_mac}",
                             [f"{len(self.devices)} devices seen so far"])

        feed = await capture_feed(self._helper, self._capture, self._seen,
                                  "ARP packets from other hosts")
        return merge(anchor, feed)

    async def _on_helper_event(self, msg: dict) -> None:
        if msg.get("event") != "arp":
            return
        ip, mac = msg.get("src", ""), msg.get("mac", "")
        # The helper now forwards requests (op 1) as well as replies, since a
        # who-has storm is how discovery looks. Both carry a usable sender
        # identity, but 0.0.0.0 is an address-probe with no sender yet — it
        # would otherwise register as a device at address zero.
        if not ip or ip == "0.0.0.0" or not mac:
            return
        if ip in self._whitelist or ip in self._own_ips:
            return
        self._seen += 1
        # Liveness of the previous owner is what separates poisoning from a
        # reused lease (see _evaluate). This path never recorded it, so every
        # spoof seen through the helper was downgraded to "lease moved".
        with self._lock:
            self._mac_seen[mac] = time.monotonic()
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
        with self._lock:
            self._mac_seen[mac] = time.monotonic()
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
            # The kernel itself moved to a new, verified MAC. Two very
            # different things look like this on the wire, and only one of
            # them is an attack:
            #   * the previous owner is still alive and answering → two MACs
            #     contend for one IP right now → poisoning, or the gateway's
            #     address changing under us → DANGEROUS, popup, dossier;
            #   * the previous owner has been silent for a while → the lease
            #     simply moved to the next device (public Wi-Fi does this
            #     all day) → worth a line in the event list, nothing more.
            # Before this split every reused lease in a café was reported as
            # "ARP spoofing — possible MITM" and got the new phone port-scanned.
            self._arp_table[ip] = kmac
            if ip in self.devices:
                self.devices[ip]["mac"] = kmac
            now = time.monotonic()
            old_alive = (now - self._mac_seen.get(prev, -_OLD_MAC_ALIVE_WINDOW)
                         < _OLD_MAC_ALIVE_WINDOW)
            is_gateway = bool(self._gw_ip) and ip == self._gw_ip
            if old_alive or is_gateway:
                return Event(
                    type=EventType.ARP_SPOOF, level=ThreatLevel.DANGEROUS,
                    message=f"ARP spoofing: {ip} changed MAC from "
                            f"{prev} to {kmac} — possible MITM",
                    data={"ip": ip, "old_mac": prev, "new_mac": kmac},
                )
            return Event(
                type=EventType.IP_MOVED, level=ThreatLevel.SUSPICIOUS,
                message=f"{ip} now belongs to {kmac} (was {prev}, silent for "
                        f"a while) — most likely a reused DHCP lease",
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
                await self._check_gateway()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug(f"ARPWatcher: gateway check failed — {exc}")

    async def _check_gateway(self) -> None:
        # Refresh own IPs — replace set so old-network IPs don't linger
        self._own_ips = await asyncio.to_thread(_get_own_ips, self.interface)

        # A new link epoch is a new network: re-learn, never compare. Only a
        # change on a link that stayed up is a candidate for an attack.
        epoch = await asyncio.to_thread(link_epoch, self.interface)
        if epoch is not None and epoch != self._epoch:
            if self._epoch is not None:
                log.info(f"ARPWatcher: link re-established on {self.interface}"
                         f" — new baseline")
                self.network_changed()
            self._epoch = epoch

        gw_ip, gw_mac = await asyncio.to_thread(_get_gateway_info, self.interface)
        if not gw_ip:
            return
        if self._gw_ip is None:
            self._gw_ip, self._gw_mac = gw_ip, gw_mac
            return
        if gw_ip != self._gw_ip:
            if self._gw_ip_pending != gw_ip:
                self._gw_ip_pending = gw_ip
                return
            self._gw_ip_pending = None
            # Same link, different router address. DHCP reassigning the
            # network is the usual reason; a rogue DHCP server is the hostile
            # one, and that is reported with evidence by the anomaly detector.
            # This line alone is not proof of anything, so it is not a popup.
            await self._bus.emit(Event(
                type=EventType.ARP_SPOOF,
                level=ThreatLevel.SUSPICIOUS,
                message=f"Default gateway changed without reconnecting: "
                        f"{self._gw_ip} → {gw_ip}",
                data={"ip": gw_ip, "old_ip": self._gw_ip},
            ))
            self._gw_ip, self._gw_mac = gw_ip, gw_mac
            self._gw_mac_pending = None
        elif gw_mac and not self._gw_mac:
            self._gw_mac = gw_mac          # resolved late: that is the baseline
        elif gw_mac and gw_mac != self._gw_mac:
            # Require the new MAC to persist across two consecutive
            # cycles — a single STALE/relay blip must not trip MITM.
            if self._gw_mac_pending != gw_mac:
                self._gw_mac_pending = gw_mac
                return
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
