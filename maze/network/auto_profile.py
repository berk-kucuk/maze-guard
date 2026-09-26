"""
Automatic profile switching.

When the attached network changes, the profile follows: networks the user has
marked trusted get HOME, everything else gets PUBLIC. The identity itself
(SSID, or the gateway's MAC on wired) comes from the shared NetworkIdentity
service rather than a poll of its own, so the profile switches at the same
instant the device inventory and the recon cache decide they are somewhere new.
"""
from maze.core.profile import Profile
from maze.utils.logger import log


class AutoProfileWatcher:
    def __init__(self, identity, trusted_networks, on_profile):
        """
        identity:         shared NetworkIdentity (engine.identity)
        trusted_networks: iterable of network ids ("wifi:SSID" / "gw:MAC")
        on_profile:       callback(Profile) invoked when the profile should change
        """
        self._identity = identity
        self._trusted = set(trusted_networks or [])
        self._on_profile = on_profile
        self._enabled = False
        self._last_profile: Profile | None = None
        self._last_net = ""
        identity.on_change(self._on_network_change)

    @property
    def interface(self) -> str:
        return self._identity.interface

    def set_trusted(self, trusted_networks) -> None:
        self._trusted = set(trusted_networks or [])
        # The trust list changing can flip the verdict for the network we are
        # already on, so re-evaluate rather than waiting for the next move.
        self._evaluate()

    def start(self) -> None:
        self._enabled = True
        self._identity.start()
        self._evaluate()

    def stop(self) -> None:
        self._enabled = False
        self._last_profile, self._last_net = None, ""

    # ── internals ────────────────────────────────────────────────────────

    def _on_network_change(self, new_id: str, _old_id: str) -> None:
        self._evaluate()

    def _evaluate(self) -> None:
        if not self._enabled:
            return
        net_id = self._identity.network_id
        if not net_id:
            return
        # Match on every alias: a network trusted under its old "gw:<MAC>" id
        # (saved when the SSID could not be read) must still count as trusted.
        aliases = getattr(self._identity, "aliases", None) or {net_id}
        trusted = bool(set(aliases) & self._trusted)
        profile = Profile.HOME if trusted else Profile.PUBLIC
        if profile == self._last_profile and net_id == self._last_net:
            return          # same verdict for the same network: nothing to say
        self._last_profile, self._last_net = profile, net_id
        log.info(f"AutoProfile: network '{net_id}' → {profile.value}")
        try:
            self._on_profile(profile)
        except Exception as exc:
            log.warning(f"AutoProfile callback failed: {exc}")
