#!/usr/bin/env bash
# =============================================================================
#  Maze Guard — privileged helper daemon setup
#
#  Installs the helper as a root systemd service so the GUI never has to ask for
#  a sudo password. Works directly against this source checkout (dev mode) — no
#  /opt install required.
#
#  Usage:
#    sudo ./scripts/setup-daemon.sh            install + enable + start
#    sudo ./scripts/setup-daemon.sh --uninstall
# =============================================================================
set -euo pipefail

SERVICE_NAME="maze.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
GROUP="maze"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$REPO_DIR/maze/helper.py"
TARGET_USER="${SUDO_USER:-$USER}"

red()   { echo -e "\033[0;31m$*\033[0m"; }
green() { echo -e "\033[0;32m$*\033[0m"; }
info()  { echo -e "\033[0;34m  [*]\033[0m $*"; }
ok()    { echo -e "\033[0;32m  [✓]\033[0m $*"; }

if [[ $EUID -ne 0 ]]; then
  red "Must run as root:  sudo $0 $*"; exit 1
fi

# Pick the Python interpreter (prefer the project venv if present).
if [[ -x "$REPO_DIR/venv/bin/python3" ]]; then
  PYTHON="$REPO_DIR/venv/bin/python3"
else
  PYTHON="$(command -v python3)"
fi

uninstall() {
  info "Stopping and disabling ${SERVICE_NAME}"
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_PATH"
  systemctl daemon-reload
  rm -rf /run/maze
  ok "Daemon removed. (The '$GROUP' group was left in place.)"
  exit 0
}

[[ "${1:-}" == "--uninstall" ]] && uninstall

# ── maze group ────────────────────────────────────────────────────────────────
if ! getent group "$GROUP" >/dev/null; then
  groupadd --system "$GROUP"
  ok "Created group '$GROUP'"
fi
if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$GROUP"; then
  usermod -aG "$GROUP" "$TARGET_USER"
  ok "Added '$TARGET_USER' to group '$GROUP' (re-login for it to take effect)"
fi

# ── systemd unit ──────────────────────────────────────────────────────────────
info "Writing ${SERVICE_PATH}"
cat > "$SERVICE_PATH" <<UNIT
[Unit]
Description=Maze Guard privileged helper
Documentation=https://github.com/berk-kucuk/maze
After=network.target

[Service]
Type=simple
ExecStart=${PYTHON} ${HELPER}
Restart=on-failure
RestartSec=2
# systemd creates/cleans /run/maze for us; the helper re-groups it to 'maze'.
# NO RuntimeDirectory=maze: /run/maze is shared with maze-tools' maze-guardd
# (guard.sock) and Maze Sentinel. RuntimeDirectory would make systemd delete
# the whole directory whenever this unit stops, destroying their files. The
# helper creates and permissions the directory itself in _ensure_sock_dir().
# Light hardening that does not interfere with firewalld / ip / sysctl / scapy.
# ProtectSystem stays 'true' (not 'strict') so firewalld can write /etc/firewalld;
# kernel-tunable and address-family locks are omitted (helper writes sysctl and
# sniffs via AF_PACKET).
ProtectHome=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectSystem=true
ProtectHostname=true
NoNewPrivileges=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Daemon running. Socket: /run/maze/maze.sock"
else
  red "Service failed to start. Check:  journalctl -u $SERVICE_NAME -e"
fi

green ""
green "Done. Note: log out/in (or run 'newgrp maze') so your session joins the '$GROUP' group."
