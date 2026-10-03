#!/usr/bin/env bash
# =============================================================================
#  Maze Guard — privileged helper daemon setup (development)
#
#  Installs the helper from this source checkout as the same sandboxed root
#  service the package ships (packaging/maze-guard.service), so the GUI run
#  from the checkout gets full functionality without a /opt install.
#
#  The code the service runs is COPIED to a root-owned directory first. Running
#  root's code straight out of the checkout — which belongs to your user —
#  meant any program in your session could edit helper.py and have it executed
#  as root on the next start. Re-run this script after changing the helper.
#
#  Usage:
#    sudo ./scripts/setup-daemon.sh            install / update + enable + start
#    sudo ./scripts/setup-daemon.sh --uninstall
# =============================================================================
set -euo pipefail

SERVICE_NAME="maze-guard.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
LEGACY_SERVICE="maze.service"          # what older versions of this script installed
DEST="/usr/local/lib/maze-guard-dev"
POLICY_DST="/usr/share/polkit-1/actions/org.mazeguard.policy"
GROUP="maze"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${SUDO_USER:-$USER}"

red()   { echo -e "\033[0;31m$*\033[0m"; }
green() { echo -e "\033[0;32m$*\033[0m"; }
info()  { echo -e "\033[0;34m  [*]\033[0m $*"; }
ok()    { echo -e "\033[0;32m  [✓]\033[0m $*"; }
die()   { red "  [✗] $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root:  sudo $0 $*"

remove_legacy() {
  if [[ -f "/etc/systemd/system/$LEGACY_SERVICE" ]]; then
    systemctl disable --now "$LEGACY_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$LEGACY_SERVICE"
    ok "Removed the old $LEGACY_SERVICE (unsandboxed, ran code from the checkout)"
  fi
}

uninstall() {
  info "Stopping and disabling ${SERVICE_NAME}"
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_PATH"
  remove_legacy
  systemctl daemon-reload
  rm -rf "$DEST"
  # Only our own socket: /run/maze is shared with maze-guardd and Maze Sentinel.
  rm -f /run/maze/maze.sock
  ok "Daemon removed. (The '$GROUP' group and the polkit policy were left in place.)"
  exit 0
}

[[ "${1:-}" == "--uninstall" ]] && uninstall

# The package installs the same unit to /usr/lib; two helpers would fight over
# one socket.
if command -v pacman >/dev/null && pacman -Q maze-guard >/dev/null 2>&1; then
  die "The maze-guard package is installed and already runs this helper. " \
      "Remove it first (sudo pacman -R maze-guard) or rebuild it from this " \
      "checkout with ./build-pkg.sh --install."
fi

# ── Interpreter: must itself be root-owned and not writable by others ─────────
PYTHON=""
for candidate in /opt/maze/venv/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]]; then PYTHON="$candidate"; break; fi
done
[[ -n "$PYTHON" ]] || die "No system Python found (/opt/maze/venv or /usr/bin/python3)."
real_py="$(readlink -f "$PYTHON")"
[[ "$(stat -c %u "$real_py")" == 0 ]] || die "$real_py is not owned by root."
[[ -z "$(find "$real_py" -perm /022)" ]] || die "$real_py is writable by non-root users."
"$PYTHON" -c "import scapy" 2>/dev/null \
  || die "$PYTHON cannot import scapy. Install maze-python (or python-scapy) first."

# ── maze group ────────────────────────────────────────────────────────────────
if ! getent group "$GROUP" >/dev/null; then
  groupadd --system "$GROUP"
  ok "Created group '$GROUP'"
fi
if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$GROUP"; then
  usermod -aG "$GROUP" "$TARGET_USER"
  ok "Added '$TARGET_USER' to group '$GROUP' (re-login for it to take effect)"
fi

# ── Root-owned copy of the code ───────────────────────────────────────────────
info "Copying the helper code to $DEST (root-owned)"
rm -rf "$DEST"
install -d -m 0755 -o root -g root "$DEST"
cp -r "$REPO_DIR/maze" "$DEST/"
find "$DEST" -name __pycache__ -type d -prune -exec rm -rf {} +
chown -R root:root "$DEST"
find "$DEST" -type d -exec chmod 0755 {} +
find "$DEST" -type f -exec chmod 0644 {} +

# ── polkit action (consent before protection is lowered) ─────────────────────
install -Dm644 "$REPO_DIR/packaging/org.mazeguard.policy" "$POLICY_DST"
ok "polkit actions: $POLICY_DST"

# ── systemd unit: the package's own definition ────────────────────────────────
remove_legacy
info "Writing ${SERVICE_PATH}"
sed -e "s|@PYTHON@|$PYTHON|" -e "s|@HELPER@|$DEST/maze/helper.py|" \
    "$REPO_DIR/packaging/maze-guard.service" > "$SERVICE_PATH"
chmod 0644 "$SERVICE_PATH"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
systemctl restart "$SERVICE_NAME"

sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Daemon running. Socket: /run/maze/maze.sock"
else
  red "Service failed to start. Check:  journalctl -u $SERVICE_NAME -e"
  exit 1
fi

green ""
green "Done. Log out/in (or run 'newgrp maze') so your session joins the '$GROUP' group."
green "After changing maze/helper.py, run this script again to update the root-owned copy."
