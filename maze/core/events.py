from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable


class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


_LEVEL_RANK = {"safe": 0, "suspicious": 1, "dangerous": 2}


def escalate(current: ThreatLevel, incoming: ThreatLevel) -> ThreatLevel:
    """The higher of two threat levels.

    The displayed level must never be decided by whichever event happened to
    arrive last: an attacker is blocked (DANGEROUS) and the reconnaissance
    that follows reports back (SUSPICIOUS) seconds later, which would
    otherwise downgrade the header while the block is still in force. Lowering
    it is a deliberate act — the reset control.
    """
    return (incoming if _LEVEL_RANK.get(incoming.value, 0)
            > _LEVEL_RANK.get(current.value, 0) else current)


class EventType(Enum):
    ARP_SPOOF      = "arp_spoof"
    IP_MOVED       = "ip_moved"          # an IP's MAC changed, old owner gone (lease reuse)
    ARP_SCAN       = "arp_scan"          # netdiscover-style L2 sweep
    ROGUE_AP       = "rogue_ap"
    ROGUE_DHCP     = "rogue_dhcp"        # unexpected DHCP server on the link
    ROGUE_RA       = "rogue_ra"          # unexpected IPv6 router on the link
    DNS_SPOOF      = "dns_spoof"
    TLS_CHANGE     = "tls_change"
    SSL_STRIP      = "ssl_strip"
    PORT_SCAN      = "port_scan"
    STEALTH_SCAN   = "stealth_scan"      # FIN / NULL / XMAS probes
    HOST_SWEEP     = "host_sweep"        # ICMP or SYN sweep across the subnet
    ANOMALY        = "anomaly"           # deviation from the learned baseline
    ATTACK_CHAIN   = "attack_chain"      # correlated multi-stage activity
    UNKNOWN_PROCESS= "unknown_process"
    DNS_LEAK       = "dns_leak"
    PROFILE_CHANGED= "profile_changed"
    DEVICE_FOUND   = "device_found"   # seen on the wire this session
    DEVICE_NEW     = "device_new"      # never seen on THIS network before
    MODULE_TOGGLED = "module_toggled"
    ENGINE_READY   = "engine_ready"
    RECON_RESULT   = "recon_result"
    IP_BLOCKED     = "ip_blocked"
    FIREWALL_CHANGED = "firewall_changed"


@dataclass
class Event:
    type: EventType
    level: ThreatLevel
    message: str
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class EventBus:
    def __init__(self):
        self._listeners: dict[EventType, list[Callable]] = {}
        self._catch_all: list[Callable] = []

    def subscribe(self, event_type: EventType, callback: Callable) -> None:
        self._listeners.setdefault(event_type, []).append(callback)

    def subscribe_all(self, callback: Callable) -> None:
        # Modules are stopped and restarted on every profile change, so a
        # blind append meant the same listener ran twice after one switch,
        # four times after two — duplicating events in the UI and the log.
        if callback not in self._catch_all:
            self._catch_all.append(callback)

    def unsubscribe_all(self, callback: Callable) -> None:
        if callback in self._catch_all:
            self._catch_all.remove(callback)

    async def emit(self, event: Event) -> None:
        # Isolate each subscriber: one raising (or the GUI callback erroring)
        # must not stop the remaining listeners — notably the engine's recon
        # catch-all and the dashboard's UI update run off the same emit.
        for cb in list(self._listeners.get(event.type, [])) + list(self._catch_all):
            try:
                await cb(event)
            except Exception:
                from maze.utils.logger import log
                log.warning(f"event subscriber failed for {event.type}", exc_info=True)
