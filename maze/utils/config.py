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
    port_scan_threshold: int = 25
    theme: str = "dark"
    language: str = "en"
    profile: str = "home"
    # Switch profile by network: a network on trusted_networks gets HOME,
    # anything else PUBLIC. On by default, because the alternative — a fresh
    # install sitting on "home" in every café until someone finds the combo —
    # is the wrong failure mode for a tool whose job is exactly that
    # judgement. Until the user marks a network trusted, every network is
    # public; the tray says so once per switch so the choice is visible.
    auto_profile_switch: bool = True
    # Bumped when a default changes in a way existing config files should
    # adopt. load_config() applies the migrations for anything older.
    config_version: int = 2
    # Lowest threat level allowed to raise a DESKTOP (tray) notification.
    # "dangerous" (default) | "suspicious" | "off"
    #
    # Everything still lands in the dashboard event list regardless — this only
    # governs the popup. SUSPICIOUS is deliberately not a popup by default: it
    # is the level used for "worth a look" heuristics (a handful of ports
    # probed, an unfamiliar process opening a socket), which on a workstation
    # fires often enough during ordinary work — running a scan, booting a VM,
    # a torrent client warming up — that the popups became noise people learn
    # to dismiss, which is worse than not showing them. Real, confirmed threats
    # (ARP spoofing, a sustained scan) are DANGEROUS and still pop up.
    notify_min_level: str = "dangerous"
    # Whether a device that has never been seen on THIS network raises a
    # desktop notification. Separate from notify_min_level because it answers a
    # different question — not "is something attacking me" but "is something
    # here that shouldn't be" — and it is the signal a home user most wants.
    notify_new_devices: bool = True
    # Whether blocking a source also blocks its hardware address. An IP block
    # is walked around by a DHCP renewal; a MAC block is not. Only meaningful
    # on the local segment — which is the only place this tool ever blocks.
    block_by_mac: bool = True
    # Set once the first-run dialog has been answered. Its absence is what
    # makes a fresh install ask; nothing else depends on it.
    first_run_done: bool = False
    # Whether a confirmed active attacker (port scan, stealth scan, correlated
    # multi-stage activity) gets a firewall drop rule automatically after
    # reconnaissance. Infrastructure (gateway, DNS), whitelisted addresses and
    # public — therefore spoofable — sources are excluded regardless.
    auto_block: bool = True
    # How long an on-demand device dossier (Devices tab → right click) stays
    # valid, in seconds. Kept well under a typical DHCP lease: an IP identifies
    # a device only until the lease moves, so old answers must not be presented
    # as current ones. Results live in memory only and never reach disk.
    device_intel_ttl: int = 900
    known_processes: list = field(default_factory=lambda: [
        # Browsers
        "firefox", "chromium", "brave", "brave-browser", "chrome",
        "chromium-browser", "opera", "vivaldi", "librewolf", "floorp",
        # VPN clients
        "protonvpn-app", "protonvpn", "proton-vpn-gnome", "openvpn",
        "wg", "wg-quick", "nordvpn", "mullvad", "expressvpn",
        "openconnect", "vpnc", "wireguard",
        # Privacy / anonymity / mesh networking (make their own outbound conns)
        "tor", "tor-real", "obfs4proxy", "snowflake-client", "i2pd",
        "mullvad-daemon", "tailscaled", "tailscale", "zerotier-one",
        # Time / sync daemons
        "chronyd", "ntpd", "systemd-timesyncd",
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
        # AI / local model servers
        "ollama", "ollama_llama_ser",
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
            # An existing config file means an existing user: they have already
            # made these choices in the interface, and greeting them with a
            # first-run wizard on upgrade would be a downgrade.
            if "first_run_done" not in data:
                cfg.first_run_done = True
            # v2: auto profile switching became the default. Every config
            # written before that carries auto_profile_switch=false — not
            # because anyone chose it, but because that was what save_config
            # wrote for the old default — so it is migrated once. Someone who
            # turns it off again from now on keeps their choice.
            if int(data.get("config_version", 1)) < 2:
                cfg.auto_profile_switch = True
                cfg.config_version = 2
            return cfg
        except Exception as e:
            from maze.utils.logger import log
            log.warning(f"Failed to load config, using defaults: {e}")
    return MazeConfig()


def save_config(cfg: MazeConfig) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in cfg.__dict__.items()}
    data["custom_profiles"] = [
        p.to_dict() if hasattr(p, "to_dict") else p
        for p in cfg.custom_profiles
    ]
    CONFIG_PATH.write_text(json.dumps(data, indent=2))
