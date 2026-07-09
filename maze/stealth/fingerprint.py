import asyncio
from maze.utils.logger import log

# These sysctl keys must also be listed in helper.py _SYSCTL_ALLOWED
_SYSCTL_RULES = [
    ("net.ipv4.ip_default_ttl",    "128"),
    ("net.ipv4.tcp_window_scaling", "0"),
]


class FingerprintProtector:
    def __init__(self):
        self._original: dict[str, str] = {}
        self._helper = None

    async def start(self, bus, helper=None) -> None:
        self._helper = helper
        if not (helper and helper.is_connected()):
            raise PermissionError(
                "FingerprintProtector needs the privileged helper to tune sysctl")
        await self._apply_via_helper(helper)

    async def stop(self) -> None:
        if self._helper and self._helper.is_connected() and self._original:
            await self._restore_via_helper(self._helper)

    async def _apply_via_helper(self, helper) -> None:
        for key, value in _SYSCTL_RULES:
            orig = await helper.sysctl_get(key)
            if orig is not None:
                self._original[key] = orig
                ok = await helper.sysctl_set(key, value)
                if ok:
                    log.info(f"FingerprintProtector: set {key}={value} (was {orig})")

    async def _restore_via_helper(self, helper) -> None:
        for key, orig_value in self._original.items():
            await helper.sysctl_set(key, orig_value)
        log.info("FingerprintProtector: sysctl values restored")
