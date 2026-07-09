import asyncio
import subprocess
from pathlib import Path

_STATE_FILE = Path("/tmp/maze-hostname-state")
_UNIT = "avahi-daemon"


class HostnameHider:
    """Stop the mDNS responder (avahi) so the machine stops advertising its
    hostname on the LAN. Uses the privileged helper when available (daemon mode);
    otherwise falls back to direct systemctl (legacy sudo / root GUI).
    """

    def __init__(self):
        self._mdns_was_running = False
        self._helper = None

    async def start(self, bus, helper=None) -> None:
        import os
        self._helper = helper
        if not (helper and helper.is_connected()) and os.getuid() != 0:
            raise PermissionError(
                "HostnameHider needs the privileged helper (or root) to stop avahi")
        self._mdns_was_running = await self._is_active()
        # Persist state so crash recovery can restart avahi even if this
        # object never sees its stop() call.
        _STATE_FILE.write_text("1" if self._mdns_was_running else "0")
        if self._mdns_was_running:
            await self._svc("stop")

    async def stop(self) -> None:
        was_running = self._mdns_was_running
        if _STATE_FILE.exists():
            was_running = was_running or _STATE_FILE.read_text().strip() == "1"
            _STATE_FILE.unlink(missing_ok=True)
        if was_running:
            await self._svc("start")
        self._mdns_was_running = False

    # ── helper / direct plumbing ──────────────────────────────────────────

    async def _is_active(self) -> bool:
        if self._helper and self._helper.is_connected():
            ok, out = await self._helper.svc("is-active", _UNIT)
            return out.strip() == "active"
        return await asyncio.to_thread(self._is_active_direct)

    async def _svc(self, action: str) -> None:
        if self._helper and self._helper.is_connected():
            await self._helper.svc(action, _UNIT)
        else:
            await asyncio.to_thread(self._svc_direct, action)

    @staticmethod
    def _is_active_direct() -> bool:
        r = subprocess.run(["systemctl", "is-active", _UNIT],
                           capture_output=True, text=True)
        return r.stdout.strip() == "active"

    @staticmethod
    def _svc_direct(action: str) -> None:
        subprocess.run(["systemctl", action, _UNIT],
                       check=False, capture_output=True)
