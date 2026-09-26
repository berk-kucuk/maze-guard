"""
Stop this machine announcing its hostname over mDNS.

Stopping ``avahi-daemon.service`` alone is not enough, and that is what this
module used to do. avahi also ships ``avahi-daemon.socket``, which systemd
keeps listening on at /run/avahi-daemon/socket and which is configured to
*start the service again* the moment any client connects. Plenty do without
being asked: nss-mdns on hosts that wire it into nsswitch.conf, CUPS looking
for printers, a file manager browsing for shares, KDE Connect. So the
responder came back on its own, and resumed answering the network with the
hostname — while the interface still showed the protection as Active.

The socket is therefore stopped first, before the service, so that killing the
service cannot immediately re-trigger it. Both are put back exactly as they
were found.
"""
import asyncio
import json
import subprocess
from pathlib import Path

from maze.core.verify import FAIL, INFO, PASS, Verdict

# Kept in the user's own config dir rather than a world-writable, predictable
# /tmp path — the latter lets another local user pre-create/symlink the file and
# poison the avahi restore state on a multi-user host.
_STATE_FILE = Path.home() / ".config" / "maze" / "hostname-state"
_UNIT = "avahi-daemon"
_SOCKET = "avahi-daemon.socket"
# Order matters on the way down: disarm the activation socket, then stop the
# responder. Reversed on the way back up.
_UNITS = (_SOCKET, _UNIT)


class HostnameHider:
    """Stop the mDNS responder (avahi) and its activation socket.

    Uses the privileged helper when available (daemon mode); otherwise falls
    back to direct systemctl (legacy sudo / root GUI).
    """

    def __init__(self):
        self._was_running: dict[str, bool] = {}
        self._unit_present = True
        self._helper = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, bus, helper=None) -> None:
        import os
        self._helper = helper
        if not (helper and helper.is_connected()) and os.getuid() != 0:
            raise PermissionError(
                "the privileged helper is not connected, so the mDNS "
                "responder cannot be stopped")
        # Whether the unit exists at all is answerable without privilege, and
        # worth answering: on a host with no avahi installed this module has
        # nothing to do, and reporting a bare "Active" would imply it had hidden
        # something. It says so instead.
        self._unit_present = await asyncio.to_thread(self._unit_exists)

        self._was_running = {}
        for unit in _UNITS:
            self._was_running[unit] = await self._is_active(unit)
        # Persist state so crash recovery can restore avahi even if this object
        # never sees its stop() call.
        self._save_state()
        for unit in _UNITS:
            if self._was_running[unit]:
                await self._svc("stop", unit)

    async def stop(self) -> None:
        # The file outlives the process; trust whichever source says a unit was
        # running, so a crash between start() and stop() still restores it.
        was = self._load_state()
        for unit, running in self._was_running.items():
            was[unit] = was.get(unit, False) or running
        _STATE_FILE.unlink(missing_ok=True)
        for unit in reversed(_UNITS):
            if was.get(unit):
                await self._svc("start", unit)
        self._was_running = {}

    # ── what the interface shows ─────────────────────────────────────────

    def status_detail(self) -> str:
        if not self._unit_present:
            return ("avahi is not installed — this machine was not "
                    "advertising itself over mDNS to begin with")
        stopped = [u for u, running in self._was_running.items() if running]
        if _UNIT in stopped:
            return ("avahi stopped and its activation socket disarmed — "
                    "hostname no longer announced on the LAN")
        if _SOCKET in stopped:
            return ("avahi was already stopped; its activation socket is now "
                    "disarmed, so a .local lookup can no longer restart it")
        return "avahi and its activation socket were already stopped"

    # ── self-test ────────────────────────────────────────────────────────

    async def verify(self) -> Verdict:
        """Ask systemd, not ourselves, whether the responder is silenced.

        Reading unit state needs no privilege, so this works whether or not the
        helper is up — and it is the same question from both sides of the
        toggle, which is what makes running it twice informative.
        """
        if not await asyncio.to_thread(self._unit_exists):
            return Verdict(INFO,
                           "avahi is not installed here, so nothing on this "
                           "machine can announce its hostname over mDNS")
        states = {}
        for unit in _UNITS:
            states[unit] = await asyncio.to_thread(self._is_active_direct, unit)
        evidence = [f"{u} is {'active' if a else 'inactive'}"
                    for u, a in states.items()]
        if not any(states.values()):
            return Verdict(PASS,
                           "the mDNS responder is stopped and its activation "
                           "socket is disarmed — this machine is not "
                           "announcing its hostname on the LAN", evidence)
        if states[_UNIT]:
            return Verdict(FAIL,
                           "the mDNS responder is running: this machine "
                           "answers .local queries with its hostname",
                           evidence)
        return Verdict(FAIL,
                       "the responder is stopped, but its activation socket is "
                       "still armed — the next .local lookup by any program on "
                       "this machine starts it again", evidence)

    # ── state file ───────────────────────────────────────────────────────

    def _save_state(self) -> None:
        try:
            _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _STATE_FILE.write_text(json.dumps(self._was_running))
        except Exception:
            pass

    @staticmethod
    def _load_state() -> dict[str, bool]:
        """What was running before, from disk.

        Also understands the single "1"/"0" a version before this one wrote,
        which meant the service only — otherwise upgrading over a running
        instance would lose the one fact the file exists to preserve.
        """
        try:
            raw = _STATE_FILE.read_text().strip()
        except Exception:
            return {}
        if raw in ("0", "1"):
            return {_UNIT: raw == "1"}
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        return {u: bool(data.get(u)) for u in _UNITS}

    # ── helper / direct plumbing ──────────────────────────────────────────

    @staticmethod
    def _unit_exists() -> bool:
        """Whether systemd knows the unit. Unprivileged, so no helper needed."""
        try:
            r = subprocess.run(
                ["systemctl", "show", "-p", "LoadState", "--value", _UNIT],
                capture_output=True, text=True, timeout=5)
            return r.stdout.strip() == "loaded"
        except Exception:
            return True     # cannot tell — assume it is there and try anyway

    async def _is_active(self, unit: str) -> bool:
        if self._helper and self._helper.is_connected():
            ok, out = await self._helper.svc("is-active", unit)
            return out.strip() == "active"
        return await asyncio.to_thread(self._is_active_direct, unit)

    async def _svc(self, action: str, unit: str) -> None:
        if self._helper and self._helper.is_connected():
            await self._helper.svc(action, unit)
        else:
            await asyncio.to_thread(self._svc_direct, action, unit)

    @staticmethod
    def _is_active_direct(unit: str) -> bool:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True)
        return r.stdout.strip() == "active"

    @staticmethod
    def _svc_direct(action: str, unit: str) -> None:
        subprocess.run(["systemctl", action, unit],
                       check=False, capture_output=True)
