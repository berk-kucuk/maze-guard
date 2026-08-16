import asyncio
import os
import subprocess
from maze.core.events import Event, EventBus, EventType, ThreatLevel

_BSSID_CONFIRM_COUNT = 3  # must persist across this many checks


def _is_wireless(interface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{interface}/wireless")


class RogueAPDetector:
    """Detect Evil Twin / Rogue Access Points.

    A genuine multi-AP WiFi network (mesh, campus, office) shares one SSID
    across dozens of BSSIDs. Roaming from one AP to another is normal.
    This detector maintains a GROWING set of known BSSIDs for the current
    SSID and only alerts when a genuinely NEW BSSID appears AND persists
    across multiple confirmation cycles — a single blip or normal roam
    does not trigger.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._is_wifi = _is_wireless(interface)
        self._known_bssids: set[str] = set()
        self._known_ssid: str | None = None
        self._pending_bssid: str | None = None
        self._pending_count: int = 0
        self._redirects_warned = False
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        if self._is_wifi:
            ssid, bssid = await asyncio.to_thread(self._current_ap)
            self._known_ssid = ssid
            if bssid:
                self._known_bssids.add(bssid)
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def _current_ap(self) -> tuple[str | None, str | None]:
        try:
            ssid = subprocess.check_output(
                ["iwgetid", self.interface, "--raw"], text=True
            ).strip() or None
            bssid = subprocess.check_output(
                ["iwgetid", self.interface, "--ap", "--raw"], text=True
            ).strip() or None
            return ssid, bssid
        except Exception:
            return None, None

    async def _monitor(self) -> None:
        await self._check_icmp_redirects()
        while True:
            await asyncio.sleep(15)
            if self._is_wifi:
                ssid, bssid = await asyncio.to_thread(self._current_ap)
                if not ssid or not bssid:
                    self._pending_bssid = None
                    self._pending_count = 0
                    continue
                if self._known_ssid and ssid == self._known_ssid:
                    if bssid not in self._known_bssids:
                        if self._pending_bssid == bssid:
                            self._pending_count += 1
                            if self._pending_count >= _BSSID_CONFIRM_COUNT:
                                self._known_bssids.add(bssid)
                                self._pending_bssid = None
                                self._pending_count = 0
                                await self._bus.emit(Event(
                                    type=EventType.ROGUE_AP,
                                    level=ThreatLevel.SUSPICIOUS,
                                    message=f"New AP detected for '{ssid}': "
                                            f"BSSID {bssid} — possible Evil Twin",
                                    data={"ssid": ssid, "bssid": bssid},
                                ))
                        else:
                            self._pending_bssid = bssid
                            self._pending_count = 1
                    else:
                        self._pending_bssid = None
                        self._pending_count = 0
                else:
                    self._known_ssid = ssid
                    self._known_bssids = {bssid}
                    self._pending_bssid = None
                    self._pending_count = 0

    async def _check_icmp_redirects(self) -> None:
        if not self._is_wifi:
            return
        try:
            path = f"/proc/sys/net/ipv4/conf/{self.interface}/accept_redirects"
            val = await asyncio.to_thread(lambda: open(path).read().strip())
            if val == "1" and not self._redirects_warned:
                self._redirects_warned = True
                await self._bus.emit(Event(
                    type=EventType.ROGUE_AP,
                    level=ThreatLevel.SUSPICIOUS,
                    message=f"ICMP redirect acceptance enabled on {self.interface} — "
                            f"an attacker on the network can reroute your traffic",
                    data={"interface": self.interface},
                ))
        except Exception:
            pass
