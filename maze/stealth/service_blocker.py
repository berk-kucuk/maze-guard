import asyncio
from maze.utils.logger import log


class ServiceBlocker:
    """Block mDNS/NetBIOS broadcast leaks via firewalld rich rules.

    Rules are added through the privileged helper daemon (running as root
    via systemd) so the GUI never prompts for a password. If the helper
    isn't connected, operations silently fail — they never fall back to
    a direct subprocess call that would trigger a polkit prompt.
    """

    _PORTS = [("udp", 5353), ("udp", 137), ("udp", 138)]

    def __init__(self):
        self._active = False
        self._helper = None

    async def start(self, bus, helper=None) -> None:
        self._helper = helper
        for proto, port in self._PORTS:
            rule = f'rule family=ipv4 port port={port} protocol={proto} drop'
            ok = await self._fw(["--permanent", "--add-rich-rule", rule])
            if not ok:
                log.warning(f"ServiceBlocker: could not block {proto}/{port}")
        await self._fw(["--reload"])
        self._active = True

    async def stop(self) -> None:
        for proto, port in self._PORTS:
            rule = f'rule family=ipv4 port port={port} protocol={proto} drop'
            await self._fw(["--permanent", "--remove-rich-rule", rule])
        await self._fw(["--reload"])
        self._active = False

    async def _fw(self, args: list[str]) -> bool:
        cmd = ["firewall-cmd"] + args
        if self._helper and self._helper.is_connected():
            return await self._helper.fw_cmd(cmd)
        return False  # no helper, no direct call — would trigger polkit
