#!/usr/bin/env bash
# =============================================================================
#  Maze Guard — Security Monitor  •  Installer
#  Supports: Arch, Debian/Ubuntu, Fedora, RHEL, openSUSE (and derivatives)
#  Usage:
#    sudo ./install.sh          — system-wide install to /opt/maze
#    ./install.sh --user        — user install to ~/.local (no root needed)
#    sudo ./install.sh --uninstall   — remove a system install
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Terminal colours ──────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${BLUE}  [*]${RESET}  $*"; }
ok()      { echo -e "${GREEN}  [✓]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}  [!]${RESET}  $*"; }
fatal()   { echo -e "${RED}  [✗]${RESET}  $*"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}▸ $*${RESET}"; }
blank()   { echo ""; }

# ── Banner ────────────────────────────────────────────────────────────────────
blank
echo -e "${BOLD}${CYAN}"
echo "  ███╗   ███╗ █████╗ ███████╗███████╗"
echo "  ████╗ ████║██╔══██╗╚══███╔╝██╔════╝"
echo "  ██╔████╔██║███████║  ███╔╝ █████╗  "
echo "  ██║╚██╔╝██║██╔══██║ ███╔╝  ██╔══╝  "
echo "  ██║ ╚═╝ ██║██║  ██║███████╗███████╗"
echo "  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝"
echo -e "${RESET}${BOLD}  Maze Guard — Security Monitor  •  Installer${RESET}"
blank

# ── Argument parsing ──────────────────────────────────────────────────────────
USER_MODE=false
DO_UNINSTALL=false

for arg in "$@"; do
  case "$arg" in
    --user)       USER_MODE=true ;;
    --uninstall)  DO_UNINSTALL=true ;;
    --help|-h)
      echo "Usage: $0 [--user] [--uninstall]"
      echo ""
      echo "  (no flags)    System-wide install to /opt/maze  [requires root]"
      echo "  --user        User install to ~/.local           [no root needed]"
      echo "  --uninstall   Remove a previously installed Maze Guard [requires root for system install]"
      exit 0
      ;;
  esac
done

# ── Install paths ─────────────────────────────────────────────────────────────
SERVICE_FILE="/etc/systemd/system/maze.service"
MAZE_GROUP="maze"

if $USER_MODE; then
  INSTALL_DIR="$HOME/.local/share/maze"
  BIN_DIR="$HOME/.local/bin"
  ICON_HICOLOR="$HOME/.local/share/icons/hicolor"
  DESKTOP_DIR="$HOME/.local/share/applications"
  AUTOSTART_DIR="$HOME/.config/autostart"
  NEED_ROOT=false
else
  INSTALL_DIR="/opt/maze"
  BIN_DIR="/usr/local/bin"
  ICON_HICOLOR="/usr/share/icons/hicolor"
  DESKTOP_DIR="/usr/share/applications"
  AUTOSTART_DIR="/etc/xdg/autostart"
  NEED_ROOT=true
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_USER="${SUDO_USER:-$USER}"
LAUNCHER="$BIN_DIR/maze"

# ── Root check ────────────────────────────────────────────────────────────────
if $NEED_ROOT && [[ $EUID -ne 0 ]]; then
  fatal "System install requires root.  Run:  sudo $0\n       Or use --user for a per-user install."
fi

# ── Uninstall path ────────────────────────────────────────────────────────────
do_uninstall() {
  step "Uninstalling Maze Guard"

  # Stop & remove the privileged helper daemon (system install only)
  if $NEED_ROOT && command -v systemctl &>/dev/null; then
    systemctl disable --now maze.service 2>/dev/null || true
    [[ -f "$SERVICE_FILE" ]] && { rm -f "$SERVICE_FILE"; systemctl daemon-reload; info "Removed maze.service"; }
    rm -rf /run/maze
  fi

  local dirs=("$INSTALL_DIR")
  local files=("$LAUNCHER" "$DESKTOP_DIR/maze.desktop" "$AUTOSTART_DIR/maze.desktop")

  for f in "${files[@]}"; do
    [[ -f "$f" ]] && { rm -f "$f"; info "Removed $f"; }
  done
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] && { rm -rf "$d"; info "Removed $d"; }
  done

  # Remove icons
  for size in 16 32 48 64 128 256 512; do
    rm -f "$ICON_HICOLOR/${size}x${size}/apps/maze.png"
  done
  command -v gtk-update-icon-cache &>/dev/null && \
    gtk-update-icon-cache -f -t "$ICON_HICOLOR" 2>/dev/null || true
  command -v update-desktop-database &>/dev/null && \
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

  ok "Maze Guard uninstalled.  (The '$MAZE_GROUP' group was left in place.)"
  exit 0
}
$DO_UNINSTALL && do_uninstall

# ── Distro detection ──────────────────────────────────────────────────────────
detect_distro() {
  local id family
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    id=$(. /etc/os-release; echo "${ID:-}")
    family=$(. /etc/os-release; echo "${ID_LIKE:-$id}")
  elif command -v lsb_release &>/dev/null; then
    id=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    family="$id"
  else
    id="unknown"; family="unknown"
  fi
  echo "$id $family"
}

read -r DISTRO_ID DISTRO_FAMILY <<< "$(detect_distro)"
info "Distribution: ${DISTRO_ID} (family: ${DISTRO_FAMILY})"

distro_is() {
  # distro_is arch|debian|rhel|fedora|suse
  local pattern="$1"
  [[ "$DISTRO_ID $DISTRO_FAMILY" =~ $pattern ]]
}

# ── System package installation ───────────────────────────────────────────────
install_system_deps() {
  step "Installing system dependencies"

  if distro_is "arch|manjaro|endeavouros|garuda|artix|cachyos"; then
    pacman -Sy --needed --noconfirm \
      python python-pip \
      nftables iproute2 \
      wireless_tools \
      python-dbus dbus \
      gcc pkg-config \
      libxcb xcb-util-cursor xcb-util-wm xcb-util-keysyms \
      || warn "Some packages may have failed — continuing"

  elif distro_is "debian|ubuntu|linuxmint|pop|elementary|kali|parrot|zorin|mx|raspbian"; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      python3 python3-pip python3-venv python3-dev \
      nftables iproute2 \
      wireless-tools \
      libdbus-1-dev dbus pkg-config \
      gcc build-essential \
      libgl1 libglib2.0-0 \
      libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
      libxcb-randr0 libxcb-render-util0 libxcb-xinerama0 libxcb-xkb1 \
      libxkbcommon-x11-0 \
      || warn "Some packages may have failed — continuing"

  elif distro_is "fedora"; then
    dnf install -y \
      python3 python3-pip python3-devel \
      nftables iproute \
      wireless-tools \
      dbus-devel dbus-glib-devel \
      gcc pkg-config \
      mesa-libGL glib2 \
      xcb-util-cursor xcb-util-keysyms xcb-util-wm \
      || warn "Some packages may have failed — continuing"

  elif distro_is "rhel|centos|almalinux|rocky|ol"; then
    dnf install -y epel-release 2>/dev/null || true
    dnf install -y \
      python3 python3-pip python3-devel \
      nftables iproute \
      dbus-devel gcc pkg-config \
      mesa-libGL \
      || warn "Some packages may have failed — continuing"

  elif distro_is "opensuse|suse"; then
    zypper --non-interactive install \
      python3 python3-pip python3-devel \
      nftables iproute2 \
      wireless-tools \
      dbus-1-devel python3-dbus-python \
      gcc pkg-config libGL1 \
      || warn "Some packages may have failed — continuing"

  else
    warn "Unknown distro '${DISTRO_ID}' — skipping package manager step."
    warn "Manually install: python3 (≥3.11), nftables, iproute2, dbus-devel, libxcb"
  fi

  ok "System dependencies done"
}

# ── Python version check ──────────────────────────────────────────────────────
find_python() {
  local candidates=(python3.13 python3.12 python3.11 python3)
  for py in "${candidates[@]}"; do
    if command -v "$py" &>/dev/null; then
      local ok
      ok=$("$py" -c "import sys; print(int(sys.version_info >= (3,11)))" 2>/dev/null)
      if [[ "$ok" == "1" ]]; then
        PYTHON="$(command -v "$py")"
        return 0
      fi
    fi
  done
  fatal "Python 3.11+ is required but was not found."
}

# ── Copy source files ─────────────────────────────────────────────────────────
install_files() {
  step "Installing application files to $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"

  rsync -a --delete \
    --exclude='venv/' --exclude='__pycache__/' --exclude='*.pyc' \
    --exclude='.git/' --exclude='*.egg-info/' \
    "$SRC_DIR/maze/"        "$INSTALL_DIR/maze/"

  cp "$SRC_DIR/main.py"         "$INSTALL_DIR/main.py"
  cp "$SRC_DIR/pyproject.toml"  "$INSTALL_DIR/pyproject.toml" 2>/dev/null || true
  cp "$SRC_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt" 2>/dev/null || true
  [[ -f "$SRC_DIR/MAZE.png" ]] && cp "$SRC_DIR/MAZE.png" "$INSTALL_DIR/MAZE.png"
  [[ -d "$SRC_DIR/assets" ]]   && cp -r "$SRC_DIR/assets" "$INSTALL_DIR/"

  ok "Files installed"
}

# ── Python virtual environment ────────────────────────────────────────────────
install_python_deps() {
  step "Setting up Python virtual environment"
  "$PYTHON" -m venv "$INSTALL_DIR/venv"
  local PIP="$INSTALL_DIR/venv/bin/pip"

  info "Upgrading pip..."
  "$PIP" install --quiet --upgrade pip

  info "Installing Python packages (this may take a minute)..."
  "$PIP" install --quiet \
    "scapy>=2.5.0"   \
    "httpx>=0.27.0"  \
    "PyQt6>=6.6.0"   \
    "qasync>=0.27.0"

  # dbus-python requires C headers — try pip first, then fall back to system package
  if ! "$PIP" install --quiet "dbus-python>=1.3.2" 2>/dev/null; then
    warn "dbus-python build failed via pip — trying system package fallback..."
    _link_system_dbus
  else
    ok "dbus-python installed via pip"
  fi

  ok "Python packages ready"
}

_link_system_dbus() {
  # Install/locate system dbus-python and symlink it into the venv
  if distro_is "arch|manjaro"; then
    pacman -S --needed --noconfirm python-dbus 2>/dev/null || true
  elif distro_is "debian|ubuntu|linuxmint|pop"; then
    apt-get install -y python3-dbus 2>/dev/null || true
  elif distro_is "fedora|rhel|centos|almalinux|rocky"; then
    dnf install -y python3-dbus 2>/dev/null || true
  elif distro_is "opensuse|suse"; then
    zypper --non-interactive install python3-dbus-python 2>/dev/null || true
  fi

  # Locate system site-packages
  local sys_site
  sys_site=$("$PYTHON" -c \
    "import sysconfig; print(sysconfig.get_path('purelib'))" 2>/dev/null || echo "")
  local venv_site
  venv_site=$("$INSTALL_DIR/venv/bin/python3" -c \
    "import sysconfig; print(sysconfig.get_path('purelib'))")

  local linked=false
  for item in dbus _dbus_bindings.so _dbus_glib_bindings.so; do
    local src="$sys_site/$item"
    [[ -e "$src" ]] && { ln -sf "$src" "$venv_site/"; linked=true; }
  done

  if $linked; then
    ok "Linked system dbus-python into venv"
  else
    warn "dbus-python not found — NetworkManager integration unavailable"
  fi
}

# ── Launcher script ───────────────────────────────────────────────────────────
create_launcher() {
  step "Creating launcher"
  mkdir -p "$BIN_DIR"
  cat > "$LAUNCHER" << LAUNCHER_EOF
#!/usr/bin/env bash
# Maze Guard launcher — generated by install.sh
exec "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/main.py" "\$@"
LAUNCHER_EOF
  chmod +x "$LAUNCHER"
  ok "Launcher: $LAUNCHER"
}

# ── Icons ─────────────────────────────────────────────────────────────────────
install_icons() {
  step "Installing icons"
  [[ ! -f "$INSTALL_DIR/MAZE.png" ]] && { warn "Icon file not found — skipping"; return; }

  for size in 16 32 48 64 128 256 512; do
    local dir="$ICON_HICOLOR/${size}x${size}/apps"
    mkdir -p "$dir"
    if command -v convert &>/dev/null; then
      convert -resize "${size}x${size}" \
        "$INSTALL_DIR/MAZE.png" "$dir/maze.png" 2>/dev/null \
        || cp "$INSTALL_DIR/MAZE.png" "$dir/maze.png"
    else
      cp "$INSTALL_DIR/MAZE.png" "$dir/maze.png"
    fi
  done

  if $NEED_ROOT; then
    command -v gtk-update-icon-cache &>/dev/null && \
      gtk-update-icon-cache -f -t "$ICON_HICOLOR" 2>/dev/null || true
  fi
  ok "Icons installed"
}

# ── .desktop file ─────────────────────────────────────────────────────────────
create_desktop_entry() {
  step "Creating .desktop entry"
  mkdir -p "$DESKTOP_DIR"
  cat > "$DESKTOP_DIR/maze.desktop" << DESKTOP_EOF
[Desktop Entry]
Version=1.1
Type=Application
Name=Maze Guard
GenericName=Network Security Monitor
Comment=Public WiFi protection — MITM detection, MAC randomization, firewall
Exec=$LAUNCHER
Icon=maze
Terminal=false
Categories=Network;Security;System;
Keywords=security;wifi;network;firewall;privacy;mitm;vpn;
StartupNotify=true
StartupWMClass=maze
X-GNOME-UsesNotifications=true
DESKTOP_EOF
  chmod +x "$DESKTOP_DIR/maze.desktop"

  if command -v desktop-file-validate &>/dev/null; then
    desktop-file-validate "$DESKTOP_DIR/maze.desktop" 2>/dev/null \
      && ok ".desktop file validated" \
      || warn ".desktop validation warning (non-fatal)"
  fi
  if $NEED_ROOT; then
    command -v update-desktop-database &>/dev/null && \
      update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
  fi
  ok ".desktop entry: $DESKTOP_DIR/maze.desktop"
}

# ── Autostart entry (start hidden in the system tray on login) ──────────────────
create_autostart_entry() {
  step "Creating autostart entry (background / tray on login)"
  mkdir -p "$AUTOSTART_DIR"
  cat > "$AUTOSTART_DIR/maze.desktop" << AUTOSTART_EOF
[Desktop Entry]
Version=1.1
Type=Application
Name=Maze Guard
GenericName=Network Security Monitor
Comment=Start Maze Guard minimized in the system tray
Exec=$LAUNCHER --background
Icon=maze
Terminal=false
Categories=Network;Security;System;
StartupNotify=false
StartupWMClass=maze
X-GNOME-Autostart-enabled=true
AUTOSTART_EOF
  chmod +x "$AUTOSTART_DIR/maze.desktop"
  ok "Autostart entry: $AUTOSTART_DIR/maze.desktop"
}

# ── File permissions (system install only) ────────────────────────────────────
set_permissions() {
  $NEED_ROOT || return
  # Owner: root. The helper itself runs as root via sudo.
  chown -R root:root "$INSTALL_DIR"
  # Let all users read/execute; venv/bin/* already has +x from pip
  find "$INSTALL_DIR" -type d -exec chmod 755 {} +
  find "$INSTALL_DIR" -type f -exec chmod 644 {} +
  find "$INSTALL_DIR/venv/bin" -type f -exec chmod 755 {} +
  chmod 755 "$INSTALL_DIR/main.py"
  chmod 755 "$INSTALL_DIR/maze/helper.py"
}

# ── Privileged helper daemon (systemd) ──────────────────────────────────────────
setup_daemon() {
  if ! $NEED_ROOT; then
    blank
    warn "User install: the privileged helper daemon needs root and was NOT installed."
    warn "Maze Guard will run in limited (detection-only) mode."
    warn "For full functionality run the system install:  sudo $0"
    return
  fi
  if ! command -v systemctl &>/dev/null; then
    warn "systemd not found — skipping daemon setup. Maze Guard will run in limited mode."
    return
  fi

  step "Setting up privileged helper daemon (no password needed at runtime)"

  local HELPER_ABS="$INSTALL_DIR/maze/helper.py"
  local VENV_PY_ABS="$INSTALL_DIR/venv/bin/python3"

  # 1. maze group — gates access to the helper socket
  if ! getent group "$MAZE_GROUP" >/dev/null; then
    groupadd --system "$MAZE_GROUP"
    ok "Created group '$MAZE_GROUP'"
  fi
  if id "$CURRENT_USER" &>/dev/null \
     && ! id -nG "$CURRENT_USER" | tr ' ' '\n' | grep -qx "$MAZE_GROUP"; then
    usermod -aG "$MAZE_GROUP" "$CURRENT_USER"
    ok "Added '$CURRENT_USER' to group '$MAZE_GROUP'"
  fi

  # 2. systemd unit
  cat > "$SERVICE_FILE" << SERVICE_EOF
[Unit]
Description=Maze Guard privileged helper
After=network.target

[Service]
Type=simple
ExecStart=$VENV_PY_ABS $HELPER_ABS
Restart=on-failure
RestartSec=2
RuntimeDirectory=maze
RuntimeDirectoryMode=0750
ProtectHome=true
ProtectControlGroups=true
ProtectKernelLogs=true

[Install]
WantedBy=multi-user.target
SERVICE_EOF
  ok "Service unit: $SERVICE_FILE"

  # 3. enable + start
  systemctl daemon-reload
  systemctl enable --now maze.service 2>/dev/null || true
  sleep 1
  if systemctl is-active --quiet maze.service; then
    ok "maze.service is running"
  else
    warn "maze.service did not start — check: journalctl -u maze.service -e"
  fi
}

# ── Uninstaller ───────────────────────────────────────────────────────────────
create_uninstaller() {
  cat > "$INSTALL_DIR/uninstall.sh" << UNINSTALL_EOF
#!/usr/bin/env bash
# Maze Guard uninstaller — generated by install.sh
set -euo pipefail

NEED_ROOT=$NEED_ROOT

if \$NEED_ROOT && [[ \$EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $INSTALL_DIR/uninstall.sh"
  exit 1
fi

echo "Removing Maze Guard..."
if \$NEED_ROOT && command -v systemctl &>/dev/null; then
  systemctl disable --now maze.service 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  rm -rf /run/maze
fi
rm -rf "$INSTALL_DIR"
rm -f  "$LAUNCHER"
rm -f  "$DESKTOP_DIR/maze.desktop"
rm -f  "$AUTOSTART_DIR/maze.desktop"

for size in 16 32 48 64 128 256 512; do
  rm -f "$ICON_HICOLOR/\${size}x\${size}/apps/maze.png"
done
command -v gtk-update-icon-cache &>/dev/null && \
  gtk-update-icon-cache -f -t "$ICON_HICOLOR" 2>/dev/null || true
command -v update-desktop-database &>/dev/null && \
  update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

echo "Maze Guard has been removed."
UNINSTALL_EOF
  chmod +x "$INSTALL_DIR/uninstall.sh"
  ok "Uninstaller: $INSTALL_DIR/uninstall.sh"
}

# ── rsync availability check ──────────────────────────────────────────────────
ensure_rsync() {
  command -v rsync &>/dev/null && return
  warn "rsync not found — installing..."
  if distro_is "arch|manjaro";              then pacman  -S --noconfirm rsync; fi
  if distro_is "debian|ubuntu|mint|pop";   then apt-get install -y rsync;    fi
  if distro_is "fedora|rhel|centos|alma";  then dnf     install -y rsync;    fi
  if distro_is "opensuse|suse";            then zypper  install -y rsync;    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  info "Install mode: $( $USER_MODE && echo 'user (~/.local)' || echo 'system (/opt/maze)')"
  info "Install target: $INSTALL_DIR"
  blank

  ensure_rsync
  $NEED_ROOT && install_system_deps
  find_python
  info "Using Python: $PYTHON ($("$PYTHON" --version))"

  install_files
  install_python_deps
  create_launcher
  install_icons
  create_desktop_entry
  create_autostart_entry
  set_permissions
  create_uninstaller

  setup_daemon

  blank
  echo -e "${GREEN}${BOLD}  ✓  Maze Guard installed successfully!${RESET}"
  blank
  echo -e "  Launch:    ${BOLD}maze${RESET}"
  echo -e "             or find Maze Guard in your application launcher"
  echo -e "  Autostart: starts hidden in the system tray on login"
  echo -e "  Uninstall: ${BOLD}sudo $INSTALL_DIR/uninstall.sh${RESET}"
  blank
  if $NEED_ROOT; then
    echo -e "  ${YELLOW}Note:${RESET} log out/in (or run ${BOLD}newgrp maze${RESET}) so your session"
    echo -e "        joins the '${BOLD}maze${RESET}' group and can reach the helper daemon."
    blank
  fi

  if $USER_MODE && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    warn "~/.local/bin is not in PATH. Add this to ~/.bashrc or ~/.zshrc:"
    echo -e "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
    blank
  fi
}

main "$@"
