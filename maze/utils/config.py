import json
from pathlib import Path
from dataclasses import dataclass, field


CONFIG_PATH = Path.home() / ".config" / "maze" / "config.json"


def _detect_interface() -> str:
    from maze.utils.network_info import get_active_physical_interface
    iface = get_active_physical_interface()
    return iface if iface != "—" else "eth0"


@dataclass
class CustomProfileConfig:
    name: str
    mac_randomize: bool = False
    hide_hostname: bool = False
    block_incoming: bool = False
    doh_enabled: bool = False
    port_scan_detect: bool = True
    process_monitor: bool = True
    fingerprint_protect: bool = False
    block_services: bool = False

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "CustomProfileConfig":
        return CustomProfileConfig(**{k: v for k, v in d.items() if k in CustomProfileConfig.__dataclass_fields__})


@dataclass
class MazeConfig:
    interface: str = field(default=None)
    mac_rotation_minutes: int = 30
    port_scan_threshold: int = 25
    theme: str = "dark"
    language: str = "en"
    profile: str = "home"
    auto_profile_switch: bool = False
    known_processes: list = field(default_factory=lambda: [
        # Browsers
        "firefox", "chromium", "brave", "brave-browser", "chrome",
        "chromium-browser", "opera", "vivaldi", "librewolf", "floorp",
        # VPN clients
        "protonvpn-app", "protonvpn", "proton-vpn-gnom", "openvpn",
        "wg", "wg-quick", "nordvpn", "mullvad", "expressvpn",
        "openconnect", "vpnc", "wireguard",
        # Privacy / anonymity / mesh networking (make their own outbound conns)
        "tor", "tor-real", "obfs4proxy", "snowflake-clien", "i2pd",
        "mullvad-daemon", "tailscaled", "tailscale", "zerotier-one",
        # Time / sync daemons
        "chronyd", "ntpd", "systemd-timesyn",
        # Music / media streaming
        "spotify", "Spotify", "spotifyd",
        "rhythmbox", "clementine", "strawberry", "lollypop",
        # Video / media
        "vlc", "mpv", "celluloid", "totem",
        # Communication
        "discord", "slack", "telegram-desktop", "signal-desktop",
        "zoom", "teams", "skype", "element-desktop", "fractal",
        "thunderbird", "evolution", "geary",
        # KDE / GNOME services
        "kdeconnectd", "kded5", "kded6", "plasmashell",
        "gvfsd", "gvfsd-http", "gvfsd-ftp",
        "gnome-online-accounts", "goa-daemon",
        "evolution-source-registry", "evolution-calendar-factory",
        # Password managers / security
        "keepassxc", "bitwarden", "1password",
        # Gaming
        "steam", "lutris", "heroic", "bottles",
        # Cloud / sync
        "dropbox", "nextcloud", "insync",
        # System services that make network calls
        "systemd", "systemd-resolved", "systemd-timesyncd",
        "NetworkManager", "avahi-daemon", "cups", "cupsd",
        "colord", "packagekitd", "fwupd", "snapd",
        "ssh-agent", "gpg-agent", "dbus-daemon",
        "pipewire", "wireplumber", "pulseaudio",
        "bluetoothd", "obexd",
        # Dev tools
        "curl", "wget", "ssh", "git", "python3", "python", "node",
        "npm", "cargo", "rustup", "code", "claude",
        "docker", "containerd", "dockerd",
        "java", "ruby",
        # Package managers
        "pacman", "apt", "apt-get", "dnf", "snap", "flatpak",
        "fwupd", "pamac", "yay", "paru",
    ])
    trusted_networks: list = field(default_factory=list)
    custom_profiles: list = field(default_factory=list)
    whitelist_ips: list = field(default_factory=list)

    def __post_init__(self):
        if self.interface is None:
            self.interface = _detect_interface()
        else:
            # Re-detect if saved interface is gone or down
            operstate = Path("/sys/class/net") / self.interface / "operstate"
            if not operstate.exists():
                self.interface = _detect_interface()
            else:
                state = operstate.read_text().strip()
                if state not in ("up", "unknown"):
                    self.interface = _detect_interface()


def load_config() -> MazeConfig:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            valid = set(MazeConfig.__dataclass_fields__)
            cfg = MazeConfig(**{k: v for k, v in data.items() if k in valid})
            # Reconstruct CustomProfileConfig objects
            cfg.custom_profiles = [
                CustomProfileConfig.from_dict(p) if isinstance(p, dict) else p
                for p in cfg.custom_profiles
            ]
            # Merge new default known_processes so existing users pick them up.
            defaults = MazeConfig.__dataclass_fields__["known_processes"].default_factory()
            cfg.known_processes = list(dict.fromkeys(cfg.known_processes + defaults))
            # Adopt new default threshold if saved value is still the old default (10).
            if cfg.port_scan_threshold == 10:
                cfg.port_scan_threshold = 25
            return cfg
        except Exception:
            pass
    return MazeConfig()


def save_config(cfg: MazeConfig) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in cfg.__dict__.items()}
    data["custom_profiles"] = [
        p.to_dict() if hasattr(p, "to_dict") else p
        for p in cfg.custom_profiles
    ]
    CONFIG_PATH.write_text(json.dumps(data, indent=2))
