"""
Anomaly and correlation engine.

The other detectors each answer one question in isolation: is this ARP reply a
lie, is this source touching too many ports. This module answers the two
questions none of them can:

* **Is the shape of the traffic itself wrong?** Host discovery — ARP who-has
  storms, ICMP sweeps, the odd probe types (timestamp, address-mask) — never
  trips a per-packet rule, because every individual packet is legitimate. It is
  the *distribution* that gives a scanner away. Same for a second DHCP server
  appearing on a link that had exactly one.

* **Do separate detections describe one attacker?** An ARP spoof and a port
  scan half a minute apart are two rows in an event log. From the same source
  they are one intrusion, and that is worth saying out loud.
"""
import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field

from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log

# Discovery windows. Deliberately short: a sweep is defined by doing many things
# quickly, and a long window would let ordinary background chatter accumulate
# into something that looks like one.
_DISCOVERY_WINDOW = 60.0
_ARP_SCAN_HOSTS   = 20      # distinct who-has targets from one source
_ICMP_SWEEP_HOSTS = 10      # distinct destinations pinged by one source
_MAC_CLAIM_LIMIT  = 5       # distinct IPs one MAC may answer for

# A source must stay quiet this long before the same anomaly is reported again.
_COOLDOWN = 600.0

# Two different hostile detections about one source inside this window are
# treated as one campaign.
_CORRELATION_WINDOW = 900.0

# ICMP types that carry no legitimate purpose on a modern network and show up
# almost exclusively in host-discovery tooling.
_RECON_ICMP = {13: "timestamp request", 17: "address-mask request"}

# Event types that count as hostile when correlating.
_HOSTILE = {
    EventType.ARP_SPOOF, EventType.ARP_SCAN, EventType.PORT_SCAN,
    EventType.STEALTH_SCAN, EventType.HOST_SWEEP, EventType.ROGUE_DHCP,
    EventType.DNS_SPOOF, EventType.SSL_STRIP, EventType.ROGUE_AP,
}


@dataclass
class _Window:
    """Set of observations from one source, valid for a fixed period."""
    started: float
    items: set = field(default_factory=set)
    packets: int = 0

    def add(self, item, now: float, window: float) -> None:
        if now - self.started > window:
            self.started = now
            self.items.clear()
            self.packets = 0
        self.items.add(item)
        self.packets += 1


class AnomalyDetector:
    """Network-shape anomalies plus cross-detector correlation."""

    def __init__(self, interface: str, whitelist: list[str] | None = None):
        self.interface = interface
        self._whitelist = set(whitelist or [])
        self._bus: EventBus | None = None
        self._helper = None
        self._gw_ip: str = ""

        self._arp_probes: dict[str, _Window] = {}
        self._icmp_probes: dict[str, _Window] = {}
        self._mac_claims: dict[str, set] = defaultdict(set)
        self._dhcp_servers: dict[str, float] = {}
        self._last_alert: dict[tuple, float] = {}

        # src -> {event_type_value: (last_ts, message)}
        self._hostile: dict[str, dict[str, tuple[float, str]]] = defaultdict(dict)
        self._chained: dict[str, float] = {}
        self._gw_task: asyncio.Task | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus = bus
        self._helper = helper
        await self._refresh_gateway()
        if helper and helper.is_connected():
            helper.on_event(self._on_packet)
        else:
            log.warning("AnomalyDetector: helper unavailable — "
                        "discovery-sweep detection is degraded")
        bus.subscribe_all(self._on_event)
        self._gw_task = asyncio.create_task(self._gateway_loop())

    async def stop(self) -> None:
        if self._helper is not None:
            self._helper.off_event(self._on_packet)
        if self._bus is not None:
            self._bus.unsubscribe_all(self._on_event)
        if self._gw_task:
            self._gw_task.cancel()
            self._gw_task = None

    async def _gateway_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            await self._refresh_gateway()

    async def _refresh_gateway(self) -> None:
        try:
            from maze.detection.arp_watch import _get_gateway_info
            gw_ip, _ = await asyncio.to_thread(_get_gateway_info, self.interface)
            if gw_ip:
                self._gw_ip = gw_ip
        except Exception:
            pass

    # ── packet feed ───────────────────────────────────────────────────────

    async def _on_packet(self, msg: dict) -> None:
        kind = msg.get("event")
        try:
            if kind == "arp":
                await self._on_arp(msg)
            elif kind == "icmp":
                await self._on_icmp(msg)
            elif kind == "dhcp":
                await self._on_dhcp(msg)
        except Exception as exc:
            log.debug(f"anomaly packet handling failed: {exc}")

    async def _on_arp(self, msg: dict) -> None:
        src = msg.get("src", "")
        mac = msg.get("mac", "")
        if not src or src in self._whitelist:
            return

        # One MAC answering for a growing list of addresses is what a poisoning
        # tool looks like from the side. Routers do it legitimately via proxy
        # ARP, so the gateway is exempt.
        if int(msg.get("op", 2)) == 2 and mac and src != self._gw_ip:
            claims = self._mac_claims[mac]
            claims.add(src)
            if len(claims) >= _MAC_CLAIM_LIMIT and self._may_alert(("macclaim", mac)):
                await self._emit(Event(
                    type=EventType.ANOMALY, level=ThreatLevel.DANGEROUS,
                    message=(f"One MAC ({mac}) is answering ARP for "
                             f"{len(claims)} different addresses — consistent "
                             f"with ARP cache poisoning"),
                    data={"mac": mac, "ip": src,
                          "claimed_ips": sorted(claims)[:20],
                          "technique": "arp_poisoning"},
                ))
            return

        if int(msg.get("op", 2)) != 1:
            return
        target = msg.get("dst", "")
        if not target:
            return
        now = time.monotonic()
        win = self._arp_probes.setdefault(src, _Window(started=now))
        win.add(target, now, _DISCOVERY_WINDOW)
        if len(win.items) >= _ARP_SCAN_HOSTS and self._may_alert(("arpscan", src)):
            await self._emit(Event(
                type=EventType.ARP_SCAN, level=ThreatLevel.SUSPICIOUS,
                message=(f"Host discovery from {src}: ARP requests for "
                         f"{len(win.items)} addresses in "
                         f"{_DISCOVERY_WINDOW:.0f}s — someone is mapping the "
                         f"network"),
                data={"src": src, "hosts_probed": len(win.items),
                      "packets": win.packets, "technique": "arp_sweep"},
            ))

    async def _on_icmp(self, msg: dict) -> None:
        src = msg.get("src", "")
        if not src or src in self._whitelist:
            return
        icmp_type = int(msg.get("type", 8))

        if icmp_type in _RECON_ICMP and self._may_alert(("icmprecon", src)):
            await self._emit(Event(
                type=EventType.HOST_SWEEP, level=ThreatLevel.SUSPICIOUS,
                message=(f"Recon probe from {src}: ICMP "
                         f"{_RECON_ICMP[icmp_type]} — a fingerprinting "
                         f"technique, not normal traffic"),
                data={"src": src, "icmp_type": icmp_type,
                      "technique": "icmp_recon"},
            ))
            return

        dst = msg.get("dst", "")
        if not dst:
            return
        now = time.monotonic()
        win = self._icmp_probes.setdefault(src, _Window(started=now))
        win.add(dst, now, _DISCOVERY_WINDOW)
        if len(win.items) >= _ICMP_SWEEP_HOSTS and self._may_alert(("ping", src)):
            await self._emit(Event(
                type=EventType.HOST_SWEEP, level=ThreatLevel.SUSPICIOUS,
                message=(f"Ping sweep from {src}: {len(win.items)} hosts "
                         f"probed in {_DISCOVERY_WINDOW:.0f}s"),
                data={"src": src, "hosts_probed": len(win.items),
                      "packets": win.packets, "technique": "ping_sweep"},
            ))

    async def _on_dhcp(self, msg: dict) -> None:
        """A second DHCP server on the link is a classic MITM setup: hand out a
        lease pointing at yourself as gateway and DNS, and the victim routes
        everything through you."""
        server = msg.get("server") or msg.get("src", "")
        if not server or server in self._whitelist:
            return
        now = time.monotonic()
        if server not in self._dhcp_servers:
            self._dhcp_servers[server] = now
            # The first server seen is the incumbent — on a healthy network it
            # is the only one, and it is usually the gateway.
            if len(self._dhcp_servers) == 1:
                return
        if len(self._dhcp_servers) > 1 and self._may_alert(("dhcp", server)):
            others = [s for s in self._dhcp_servers if s != server]
            await self._emit(Event(
                type=EventType.ROGUE_DHCP, level=ThreatLevel.DANGEROUS,
                message=(f"Second DHCP server on this network: {server} "
                         f"(existing: {', '.join(others[:3])}) — a rogue lease "
                         f"can redirect your gateway and DNS"),
                data={"src": server, "ip": server,
                      "known_servers": sorted(self._dhcp_servers),
                      "technique": "rogue_dhcp"},
            ))

    # ── correlation ───────────────────────────────────────────────────────

    async def _on_event(self, event: Event) -> None:
        """Watch the bus for hostile findings and join them up by source."""
        if event.type not in _HOSTILE:
            return
        src = (event.data or {}).get("src") or (event.data or {}).get("ip")
        if not src:
            return
        now = time.monotonic()
        seen = self._hostile[src]
        seen[event.type.value] = (now, event.message)
        # Forget stages that have aged out of the campaign window.
        for kind, (ts, _) in list(seen.items()):
            if now - ts > _CORRELATION_WINDOW:
                del seen[kind]
        if len(seen) < 2:
            return
        if now - self._chained.get(src, 0.0) < _COOLDOWN:
            return
        self._chained[src] = now
        stages = sorted(seen)
        await self._emit(Event(
            type=EventType.ATTACK_CHAIN, level=ThreatLevel.DANGEROUS,
            message=(f"Coordinated attack from {src}: "
                     f"{len(stages)} distinct techniques "
                     f"({', '.join(s.replace('_', ' ') for s in stages)}) "
                     f"within {_CORRELATION_WINDOW / 60:.0f} minutes"),
            data={"src": src, "ip": src, "stages": stages,
                  "technique": "multi_stage"},
        ))

    # ── helpers ───────────────────────────────────────────────────────────

    def _may_alert(self, key: tuple) -> bool:
        now = time.monotonic()
        if now - self._last_alert.get(key, 0.0) < _COOLDOWN:
            return False
        self._last_alert[key] = now
        return True

    async def _emit(self, event: Event) -> None:
        if self._bus:
            await self._bus.emit(event)
