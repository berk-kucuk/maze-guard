<div align="center">

# MAZE GUARD

**Public WiFi Security Monitor**

*MITM detection · firewalld integration · Packet analysis*

---

![Dashboard](screenshots/dashboard.png)
![Events](screenshots/events.png)
---

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python)](https://python.org)
[![PyQt6](https://img.shields.io/badge/UI-PyQt6-green?style=flat-square)](https://pypi.org/project/PyQt6/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kernel.org)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](LICENSE)

</div>

---

## What is Maze Guard?

Maze Guard is a Linux desktop application that monitors your network in real time and alerts you to threats commonly found on public WiFi networks — coffee shops, airports, hotels. It detects active attacks (ARP spoofing, port scans, Evil Twin APs, DNS poisoning), manages firewall rules through firewalld, and gives you one-click tools to block IPs and ports without breaking your internet connection.

The GUI runs as your normal user. A small privileged helper runs as a **systemd daemon** (root) that handles packet capture and firewall rules. Because the daemon is started by systemd, the GUI never needs your password — credential handling is removed entirely, which closes off the password-prompt privilege-escalation surface.

---

## Features

### Detection & Monitoring
| Module | What it detects |
|---|---|
| **ARP Watcher** | ARP spoofing, gateway MAC/IP changes |
| **Port Scan Detector** | SYN sweeps by distinct-port breadth, plus FIN/NULL/XMAS stealth probes, with per-source evidence (ports, rate, duration) |
| **Anomaly & Correlation** | ARP host-discovery storms, ICMP ping sweeps and recon probes, rogue DHCP servers, one MAC claiming many IPs — and joins separate detections from one source into a single attack chain |
| **DNS Validator** | DNS poisoning (cross-checks 3 DoH resolvers) |
| **DNS Leak Preventer** | Plaintext DNS queries escaping VPN tunnel |
| **TLS Monitor** | Certificate hash changes for canary hosts |
| **SSL Strip Detector** | HTTP downgrade attacks on known-HTTPS hosts |
| **Rogue AP Detector** | Evil Twin APs (BSSID changes), ICMP redirects |
| **Process Monitor** | Unknown processes making external connections |

### Protection
| Feature | Description |
|---|---|
| **Firewall Control** | Start/stop firewalld itself, and toggle the inbound-DROP shield, from the Protection tab — with live state read back from the firewall, not remembered in the UI |
| **firewalld Integration** | Rich rules on the *actual* default zone (IPv4 and IPv6), each carrying a rate-limited kernel log line so every block is auditable |
| **Hostname Hiding** | Disables mDNS/Avahi to hide device hostname on LAN |
| **TCP Fingerprint** | Randomizes TTL and TCP window scaling via sysctl |
| **Service Blocker** | Closes listening services on untrusted networks |

### Interface
- **Dashboard** — Live network info, firewall status, threat level, bandwidth monitor (↓/↑ per second), port scan table
- **Threats** — One dossier per attacking source: severity score, identity (MAC, vendor, hostname, OS), techniques used, ports they probed, what they are running, full timeline, and Block / Scan Source / Export Report actions
- **Events** — Filterable event log (All / Suspicious / Dangerous), text search, CSV export
- **Firewall** — Add/remove blocked IPs and ports with instant feedback
- **Devices** — All discovered LAN devices with MAC addresses
- **Connections** — Live process→IP connection map
- **Protection** — Per-module toggle switches
- **Settings** — Threshold tuning, process whitelist, IP whitelist, autostart toggle

### Other
- **IP Reconnaissance** — Auto-triggered on confirmed attacks (and on demand): reverse DNS, NetBIOS and mDNS names, MAC vendor, ~90-port sweep with service banners, TLS certificate identity, HTTP server and page title, OS fingerprint, latency, and a risk score with plain-language findings ("port 4444 open — Metasploit default handler port"). Only ever runs against on-link private addresses, never a spoofable public source
- **Incident Records** — Every hostile source is filed to `~/.local/share/maze-guard/`: an append-only evidence journal plus a dossier snapshot that survives restarts, exportable as a Markdown incident report
- **Custom Profiles** — Create named security profiles with per-feature toggles
- **Persistent Log** — All events written to `~/.config/maze/maze.log` (rotating, 2 MB × 3)
- **System Tray** — Starts hidden in the tray on login (autostart); click the tray icon to show the window; desktop notifications for dangerous events
- **Session Summary** — Event count breakdown shown on quit
- **English + Turkish** UI with live language switching

---

## Architecture

```
┌──────────────────────────────────────────────┐
│  GUI Process  (normal user, no password)     │
│                                              │
│  PyQt6 + qasync  ──►  MazeEngine            │
│                           │                  │
│                    HelperClient              │
│                           │  Unix socket     │
└───────────────────────────┼──────────────────┘
              /run/maze/maze.sock (root:maze 0660)
┌───────────────────────────┼──────────────────┐
│  Helper Daemon (root, systemd: maze.service) │
│                           ▼                  │
│   scapy (ARP/TCP/ICMP/DHCP) ───► push events│
│   firewalld (firewall rules)                  │
│   sysctl (TCP fingerprint)                   │
└──────────────────────────────────────────────┘
```

The helper runs as a systemd service and publishes a Unix socket at `/run/maze/maze.sock`, owned `root:maze` with mode `0660`. Only members of the `maze` group can reach it — enforced both by file permissions and an in-process `SO_PEERCRED` group-membership check. All firewall-cmd operations go through a strict allowlist of safe flags (`--add-rich-rule`, `--remove-rich-rule`, `--reload`, `--zone`, `--permanent`, `--list-rich-rules`, `--list-all`, `--set-default-zone`, `--get-default-zone`, `--set-target=DROP|default`) plus known-safe zone names. Any other argument is rejected before reaching a subprocess call.

Rich rules are matched **in full** against fixed patterns rather than by prefix, so a legal-looking `source address=` clause cannot be extended with an `accept`, `masquerade` or `forward-port` action. The action is pinned to `drop`, catch-all sources (`0.0.0.0/0`, `::/0`) are refused so the channel cannot be used to black-hole the host, and the optional log clause is pinned to a `MAZE-` prefix at a capped rate. Service control is a separate command limited to the single unit `firewalld`, and every call is logged by the daemon.

---

## Requirements

- **OS:** Linux (kernel 4.x+, any distribution)
- **Python:** 3.11 or newer
- **System tools:** `firewalld`, `iproute2`, `dbus`
- **Optional:** `wireless-tools` (WiFi SSID/BSSID detection), `imagemagick` (icon resizing)

---

## Installation

### Arch Linux (AUR)

```bash
# with paru
paru -S maze

# with yay
yay -S maze
```

The AUR package installs Maze Guard to `/opt/maze-guard` and creates an isolated Python venv at `/opt/maze-guard/venv` — no system Python packages are modified.

---

### Any Linux distribution (install script)

```bash
git clone https://github.com/berk-kucuk/maze-guard.git
cd maze

# System-wide install to /opt/maze-guard  (requires root)
sudo ./install.sh

# Per-user install to ~/.local  (no root needed)
./install.sh --user
```

The script detects your distribution and installs system dependencies automatically (Arch, Debian/Ubuntu, Fedora, RHEL, openSUSE and derivatives).

After install, launch from your application menu or run:

```bash
maze
```

To uninstall:

```bash
sudo /opt/maze-guard/uninstall.sh
```

---

### From source (development)

```bash
git clone https://github.com/berk-kucuk/maze-guard.git
cd maze

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python main.py
```

---

## First Launch

Maze Guard **never asks for a password**. A system install registers the privileged helper as a systemd service (`maze.service`) that starts at boot, and the GUI simply connects to it over `/run/maze/maze.sock`.

A `maze` group gates access to that socket, and your user is added to it during install. **Log out and back in once** (or run `newgrp maze`) so your desktop session picks up the new group membership — until then the GUI runs in limited (detection-only) mode.

The GUI always runs as your normal user; only the helper runs as root. If the daemon is not running for any reason, the GUI degrades gracefully to limited mode instead of prompting.

### Running from a source checkout

If you cloned the repo and want the daemon without a full `/opt` install:

```bash
sudo ./scripts/setup-daemon.sh        # install + enable maze.service, add you to 'maze'
# ... and to remove it:
sudo ./scripts/setup-daemon.sh --uninstall
```

---

## Usage

### Checking that everything works

```bash
maze-guard --doctor
```

Exercises every feature against this machine — external tools, the privileged
helper and whether it is up to date, firewalld and the inbound shield, the
polkit action and whether an agent can show its prompt, each detection module's
start/stop, all three DoH resolvers, the TLS canaries and a
live recon probe — and prints PASS/WARN/FAIL with the fix for anything broken.
Exit status is non-zero if any check failed, so it can gate a deployment.

The check exists because the failure that matters for a security tool is not a
crash, it is a module that reports *Active* while silently doing nothing.

### Profiles

Select a security profile from the top bar:

| Profile | Modules active |
|---|---|
| **Home** | ARP watch, DNS validation, TLS monitoring |
| **Public** | All detection modules + port scan detector |
| **Paranoid** | All modules + process monitor + fingerprint protection |
| **Manual** | Nothing started — you control each module individually |

You can also create **custom profiles** with the **`+`** button next to the profile selector.

### Blocking IPs and ports

**Right-click** any event in the Events tab or any row in the Dashboard scan table to block the source IP. In the Firewall tab you can add arbitrary IPs/CIDRs and port numbers with TCP/UDP/Both selectors.

All rules use firewalld rich rules with `drop` action — the firewall only drops what you explicitly add and never affects outbound traffic, so you can't accidentally brick your connection by blocking too much.

### Exporting events

In the **Events** tab, click **Export** to save the currently visible events (respecting active filters) to a CSV file.

### Autostart

The installer adds an autostart entry (`maze.desktop` with `Exec=maze --background`) so Maze Guard launches **hidden in the system tray** on every login — the detection engine starts in the background without opening a window. Click the tray icon to show the dashboard; closing the window minimizes it back to the tray. System installs write `/etc/xdg/autostart/maze.desktop`; user installs write `~/.config/autostart/maze.desktop`.

---

## Configuration

Config is stored at `~/.config/maze/config.json` and is updated automatically when you change settings in the UI.

```json
{
  "interface": "enp42s0",
  "theme": "dark",
  "language": "en",
  "port_scan_threshold": 10,
  "known_processes": ["firefox", "brave", "curl", "..."],
  "whitelist_ips": [],
  "custom_profiles": []
}
```

| Key | Description |
|---|---|
| `interface` | Network interface to monitor (auto-detected if missing or down) |
| `port_scan_threshold` | SYN packets from one IP before a SUSPICIOUS alert fires |
| `known_processes` | Processes that will never trigger "unknown process" alerts |
| `whitelist_ips` | IPs ignored by all detectors (gateway, trusted servers, etc.) |
| `custom_profiles` | User-defined profiles saved from the `+` dialog |

---

## Event levels

| Level | Color | Meaning |
|---|---|---|
| **Safe** | Green | Informational — new device seen, profile changed |
| **Suspicious** | Orange | Possible threat — DNS disagreement, port scan started, DNS leak |
| **Dangerous** | Red | Active attack — ARP spoofing, gateway MAC change, port scan escalation |

Dangerous events trigger a **desktop notification** via the system tray and automatically kick off **reconnaissance** against the attacker (identity, services, OS, risk findings). The result is filed in that source's dossier on the **Threats** tab, where it can be blocked, re-scanned, or exported as an incident report.

---

## Security model

- **No password in the GUI, no polkit, no setcap, no SUID bit.** The privileged helper runs as a systemd-managed root daemon; the GUI only talks to it over a Unix socket. The GUI never handles credentials, so a malicious app cannot phish a sudo password through it, and a compromised GUI process cannot escalate beyond what the helper exposes.
- **Helper allowlist.** Only a curated set of `firewall-cmd` flags is permitted (`--add-rich-rule`, `--remove-rich-rule`, `--reload`, `--list-all`, `--list-rich-rules`, `--set-default-zone`, `--get-default-zone`, `--set-target=DROP|default`, `--permanent`, `--zone`). Every argument (IP, interface name, zone name, sysctl key) is validated before reaching a subprocess call, and rich rules are matched in full against fixed `drop`-only patterns. Service control is a separate, logged command that can address exactly one unit: `firewalld`.
- **Group-gated socket + peer verification.** The socket is `root:maze` mode `0660`, so only `maze`-group members can open it, and the helper additionally re-checks each caller's group membership via `SO_PEERCRED`. Processes running as other users cannot send commands.
- **Adding protection is free; removing it needs consent.** Group membership answers "is this the desktop user?", which is *not* the right question for a destructive request — anything running as that user, invited or not, passes it. So stopping the firewall, lowering the inbound shield and removing a block on an attacker each require polkit authorisation (`org.mazeguard.disable-protection`), and the caller is pinned as `pid,start-time,uid` so a recycled pid cannot inherit somebody else's approval. Blocking an attacker, raising the shield and starting the firewall stay unauthenticated — including the automatic block, which has no user present to answer a prompt. Malware running as you can raise the dialog; it cannot answer it.
- **No arbitrary execution.** The helper exposes a fixed command set. Every argument is checked against an allowlist or a regex, commands are executed as argument lists (never through a shell), and there is no file-read, file-write or run-anything API. `--set-default-zone` is deliberately absent: Maze Guard never sets the default zone, and permitting it would have allowed `--set-default-zone trusted` — a one-line firewall bypass.
- **Every state change is audited.** Rule changes, service control and sysctl writes are logged to the journal with the calling `pid`, `uid` and program name (`journalctl -u maze-guard.service`). Read-only polling is not logged, so the lines that matter stay visible.
- **Default-zone rich rules.** Maze Guard adds and removes explicit rich rules on the *active* default zone, whatever it is. Removing a rule restores the previous state instantly. The one global change it makes is the inbound shield, which sets that zone's target to `DROP`; it is a labelled toggle in the Protection tab, is restored on Quit, and is read back from firewalld rather than remembered, so the button always matches reality.
- **Auto-blocking is narrow and switchable.** A firewall drop rule is added automatically only for a *confirmed active attack* — a port scan, a stealth (FIN/NULL/XMAS) scan, or two different techniques correlated to one source — and only after reconnaissance. The gateway, DNS servers and whitelisted addresses are never blocked, and public source addresses are ignored entirely because a packet's source IP is trivially forged and blocking on it would let an attacker cut you off from anything they name. Turn it off in Settings → *Automatically block confirmed attackers*; everything else remains alert-and-inform.
- **Recon only targets on-link private addresses.** For the same spoofing reason, the active scan that builds an attacker dossier never runs against a public IP, and never against infrastructure.

---

## Project structure

```
maze/
├── core/
│   ├── engine.py          # Module orchestration, event bus, recon trigger
│   ├── events.py          # Event types, threat levels
│   ├── incident.py        # Attacker dossiers, scoring, evidence journal
│   └── profile.py         # Built-in profile definitions
├── detection/
│   ├── anomaly.py         # Discovery sweeps, rogue DHCP, attack correlation
│   ├── arp_watch.py       # ARP spoofing + gateway change detection
│   ├── dns_validator.py   # DoH cross-validation (canary domains)
│   ├── rogue_ap.py        # Evil Twin + ICMP redirect check
│   ├── ssl_strip.py       # SSL strip detection
│   └── tls_monitor.py     # TLS cert hash monitoring (canary hosts)
├── protection/
│   ├── dns_leak.py        # Plaintext DNS leak detector
│   ├── firewall.py        # firewalld control: service, shield, rich rules
│   ├── port_scanner.py    # SYN-breadth + stealth-flag scan detection
│   └── process_map.py     # Unknown process connection monitor
├── stealth/
│   ├── fingerprint.py     # TCP fingerprint obfuscation (sysctl via helper)
│   ├── hostname_hide.py   # mDNS/Avahi disable
│   └── service_blocker.py # Close listening services
├── gui/
│   ├── dashboard.py       # Main window, tray, session summary
│   ├── privilege.py       # Connect to the helper daemon (no password)
│   └── widgets/
│       ├── dashboard_view.py   # Cards, bandwidth monitor, scan table
│       ├── event_list.py       # Filterable event log + CSV export
│       ├── firewall_view.py    # IP/port block manager
│       ├── settings_view.py    # Thresholds, whitelist, autostart, auto-block
│       ├── threats_view.py     # Attacker dossiers + block/scan/export
│       └── profile_dialog.py  # Custom profile creator
├── utils/
│   ├── config.py          # Config load/save, CustomProfileConfig
│   ├── logger.py          # Rotating file + console logger
│   ├── network_info.py    # Interface info, firewall status
│   └── recon.py           # Attacker reconnaissance + risk scoring
├── helper.py              # Privileged daemon (runs as root via systemd)
└── helper_client.py       # Async client for the helper socket
```

---

## License

GPL3 — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built for Linux · Tested on Arch Linux · PyQt6 + qasync + scapy</sub>
</div>
