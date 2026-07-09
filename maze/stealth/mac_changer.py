import asyncio
import random
import subprocess
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log


def _random_mac() -> str:
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    mac[0] = (mac[0] & 0xFC) | 0x02  # locally administered, unicast
    return ":".join(f"{b:02x}" for b in mac)


def _renew_dhcp(iface: str) -> None:
    """Try to renew DHCP lease after MAC change."""
    for cmd in (
        ["dhcpcd", "-n", iface],
        ["dhclient", iface],
        ["nmcli", "device", "reapply", iface],
    ):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=8)
            if result.returncode == 0:
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    log.warning(f"MACChanger: could not renew DHCP on {iface}")


class MACChanger:
    def __init__(self, interface: str, rotation_minutes: int = 30):
        self.interface = interface
        self.rotation_seconds = rotation_minutes * 60
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._helper = None

    async def start(self, bus: EventBus, helper=None) -> None:
        import os
        self._bus = bus
        self._helper = helper
        if not (helper and helper.is_connected()) and os.getuid() != 0:
            raise PermissionError(
                "MACChanger needs the privileged helper (or root) to change the MAC")
        # Do not randomize immediately — only rotate on schedule.
        # Immediate MAC change breaks DHCP and active connections.
        self._task = asyncio.create_task(self._rotate())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def randomize(self) -> str:
        # Don't rotate while a VPN tunnel is active — changing MAC triggers
        # DHCP renewal which drops the tunnel and can leak the real IP briefly.
        from maze.utils.network_info import get_active_vpn_interfaces
        vpn_ifaces = await asyncio.to_thread(get_active_vpn_interfaces)
        if vpn_ifaces:
            log.info(f"MACChanger: VPN active ({vpn_ifaces}), skipping MAC rotation")
            return ""

        mac = _random_mac()
        if self._helper and self._helper.is_connected():
            ok = await self._helper.set_mac(self.interface, mac)
        else:
            ok = await asyncio.to_thread(self._apply_direct, mac)

        if ok:
            # Renew DHCP so network stays up after MAC change
            await asyncio.to_thread(_renew_dhcp, self.interface)
            if self._bus:
                await self._bus.emit(Event(
                    type=EventType.MAC_CHANGED,
                    level=ThreatLevel.SAFE,
                    message=f"MAC address changed: {self.interface} → {mac}",
                    data={"interface": self.interface, "mac": mac},
                ))
        return mac

    def _apply_direct(self, mac: str) -> bool:
        try:
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "address", mac], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            log.warning(f"MACChanger direct apply failed: {e}")
            return False

    async def _rotate(self) -> None:
        while True:
            await asyncio.sleep(self.rotation_seconds)
            await self.randomize()
