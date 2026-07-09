from dataclasses import dataclass
from enum import Enum


class Profile(Enum):
    HOME = "home"
    PUBLIC = "public"
    PARANOID = "paranoid"
    MANUAL = "manual"


@dataclass
class ProfileConfig:
    mac_randomize: bool
    hide_hostname: bool
    block_incoming: bool
    doh_enabled: bool
    port_scan_detect: bool
    process_monitor: bool
    fingerprint_protect: bool
    block_services: bool = False   # block mDNS/NetBIOS service-discovery leaks


PROFILES: dict[Profile, ProfileConfig] = {
    # Trusted home network: passive detection only, no system changes.
    Profile.HOME: ProfileConfig(
        mac_randomize=False,
        hide_hostname=False,
        block_incoming=False,
        doh_enabled=True,
        port_scan_detect=True,
        process_monitor=True,
        fingerprint_protect=False,
        block_services=False,
    ),
    # Untrusted public WiFi: hide identity, block unsolicited inbound.
    Profile.PUBLIC: ProfileConfig(
        mac_randomize=True,
        hide_hostname=True,
        block_incoming=True,
        doh_enabled=True,
        port_scan_detect=True,
        process_monitor=True,
        fingerprint_protect=True,
        block_services=False,
    ),
    # Maximum stealth: everything Public does, plus mDNS/NetBIOS service blocking.
    Profile.PARANOID: ProfileConfig(
        mac_randomize=True,
        hide_hostname=True,
        block_incoming=True,
        doh_enabled=True,
        port_scan_detect=True,
        process_monitor=True,
        fingerprint_protect=True,
        block_services=True,
    ),
    # Manual: nothing auto-applied — the user toggles modules by hand.
    Profile.MANUAL: ProfileConfig(
        mac_randomize=False,
        hide_hostname=False,
        block_incoming=False,
        doh_enabled=False,
        port_scan_detect=False,
        process_monitor=False,
        fingerprint_protect=False,
        block_services=False,
    ),
}


class ProfileManager:
    def __init__(self):
        self.current = Profile.MANUAL
        self._listeners: list = []

    def set(self, profile: Profile) -> None:
        self.current = profile
        for cb in self._listeners:
            cb(profile)

    @property
    def config(self) -> ProfileConfig:
        return PROFILES[self.current]

    def on_change(self, callback) -> None:
        self._listeners.append(callback)
