import asyncio
import subprocess
from maze.utils.logger import log

# Imported lazily to avoid circular import at module load time
_INIT_RULESET: str | None = None


def _load_ruleset() -> str:
    global _INIT_RULESET
    if _INIT_RULESET is None:
        from maze.protection.firewall import _INIT_RULESET as rs
        _INIT_RULESET = rs
    return _INIT_RULESET


class ServiceBlocker:
    """Block mDNS/NetBIOS broadcast leaks through the Maze firewall table.

    Runs its nftables changes through the privileged helper when available
    (daemon mode, GUI is unprivileged); otherwise it edits nftables directly,
    which only works when the process itself is root.
    """

    _PORTS = [("udp", 5353), ("udp", 137), ("udp", 138)]

    def __init__(self):
        self._active = False
        self._helper = None

    async def start(self, bus, helper=None) -> None:
        import os
        self._helper = helper
        if not (helper and helper.is_connected()) and os.getuid() != 0:
            raise PermissionError(
                "ServiceBlocker needs the privileged helper (or root) to edit nftables")
        await self._ensure_ruleset()
        for proto, port in self._PORTS:
            ok = await self._nft([
                "nft", "add", "element", "inet", "maze_firewall",
                f"blocked_ports_{proto}", "{", str(port), "}",
            ])
            if not ok:
                log.warning(f"ServiceBlocker: could not block {proto}/{port}")
        self._active = True

    async def stop(self) -> None:
        for proto, port in self._PORTS:
            await self._nft([
                "nft", "delete", "element", "inet", "maze_firewall",
                f"blocked_ports_{proto}", "{", str(port), "}",
            ])
        self._active = False

    # ── helper / direct plumbing ──────────────────────────────────────────

    async def _ensure_ruleset(self) -> None:
        """Create the maze_firewall table if it doesn't exist yet."""
        if self._helper and self._helper.is_connected():
            # nft_apply is idempotent for our additive ruleset.
            await self._helper.nft_apply(_load_ruleset())
        else:
            await asyncio.to_thread(self._ensure_ruleset_direct)

    async def _nft(self, args: list[str]) -> bool:
        if self._helper and self._helper.is_connected():
            return await self._helper.fw_cmd(args)
        return await asyncio.to_thread(self._nft_direct, args)

    @staticmethod
    def _ensure_ruleset_direct() -> None:
        r = subprocess.run(["nft", "list", "table", "inet", "maze_firewall"],
                           capture_output=True)
        if r.returncode != 0:
            subprocess.run(["nft", "-f", "-"], input=_load_ruleset(),
                           text=True, capture_output=True)

    @staticmethod
    def _nft_direct(args: list[str]) -> bool:
        r = subprocess.run(args, capture_output=True, text=True, check=False)
        return r.returncode == 0
