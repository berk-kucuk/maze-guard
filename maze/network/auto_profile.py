"""
Automatic profile switching.

Polls the identity of the network attached to the monitored interface. When it
changes, the profile is switched: trusted networks (listed in the config) get
the HOME profile, everything else gets PUBLIC. Dependency-free — it shells out
to `iwgetid`/`ip` via network_info rather than talking to NetworkManager/D-Bus,
so it works the same on any Linux with or without NetworkManager.
"""
import asyncio

from maze.core.profile import Profile
from maze.utils.logger import log
from maze.utils.network_info import current_network_id

_POLL_INTERVAL = 15  # seconds


class AutoProfileWatcher:
    def __init__(self, interface: str, trusted_networks, on_profile):
        """
        interface:        iface to watch (e.g. wlan0)
        trusted_networks: iterable of network ids ("wifi:SSID" / "gw:MAC")
        on_profile:       callback(Profile) invoked when the profile should change
        """
        self.interface = interface
        self._trusted = set(trusted_networks or [])
        self._on_profile = on_profile
        self._task: asyncio.Task | None = None
        self._last_id: str | None = None

    def set_trusted(self, trusted_networks) -> None:
        self._trusted = set(trusted_networks or [])
        # Force re-evaluation on the next poll.
        self._last_id = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        while True:
            try:
                net_id = await asyncio.to_thread(current_network_id, self.interface)
                if net_id and net_id != self._last_id:
                    self._last_id = net_id
                    profile = (Profile.HOME if net_id in self._trusted
                               else Profile.PUBLIC)
                    log.info(f"AutoProfile: network '{net_id}' → {profile.value}")
                    self._on_profile(profile)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(f"AutoProfileWatcher error: {exc}")
            await asyncio.sleep(_POLL_INTERVAL)
