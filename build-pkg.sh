#!/usr/bin/env bash
# =============================================================================
#  Maze Guard — local Arch package builder
#
#  Builds a maze-guard-<version>-<rel>-<arch>.pkg.tar.zst straight from the
#  current working tree (uncommitted changes included), using packaging/PKGBUILD.
#  The package version is read from maze/__init__.py so it always matches the
#  code being built.
#
#  Usage:
#    ./build-pkg.sh              build the package into ./dist-pkg/
#    ./build-pkg.sh --install    build, pacman -U the result, restart the daemon
#    ./build-pkg.sh --no-restart with --install: skip the daemon restart
#    ./build-pkg.sh --clean      remove ./dist-pkg/ and exit
# =============================================================================
set -euo pipefail

# ── Locate the repo (this script lives at the repo root) ──────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_SRC="$ROOT/packaging"
OUT="$ROOT/dist-pkg"

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
else
  GREEN=''; BLUE=''; YELLOW=''; RED=''; RESET=''
fi
info() { echo -e "${BLUE}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

DO_INSTALL=false
DO_RESTART=true
for arg in "$@"; do
  case "$arg" in
    --install)    DO_INSTALL=true ;;
    --no-restart) DO_RESTART=false ;;
    --clean)      rm -rf "$OUT"; ok "Removed $OUT"; exit 0 ;;
    -h|--help)    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'; exit 0 ;;
    *)            die "Unknown option: $arg" ;;
  esac
done

UNIT="maze-guard.service"

# ── Restart the privileged helper onto the freshly installed code ─────────────
# The pacman hook runs `systemctl try-restart`, which does nothing at all when
# the unit is enabled but not currently running — and a helper left on the old
# code is the worst failure mode there is: the GUI looks fine, but every command
# added since the last restart silently fails. Restart unconditionally, then say
# out loud whether it came back.
restart_daemon() {
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd not found — start the helper yourself: sudo $UNIT"
    return
  fi
  if ! systemctl list-unit-files "$UNIT" >/dev/null 2>&1; then
    warn "$UNIT is not installed — skipping restart"
    return
  fi

  info "Restarting $UNIT ..."
  sudo systemctl daemon-reload || warn "daemon-reload failed"
  if sudo systemctl restart "$UNIT"; then
    sleep 1
    if systemctl is-active --quiet "$UNIT"; then
      local since
      since="$(systemctl show -p ActiveEnterTimestamp --value "$UNIT" 2>/dev/null)"
      ok "$UNIT running${since:+ (since $since)}"
    else
      warn "$UNIT did not come back — check: journalctl -u $UNIT -e"
    fi
  else
    warn "Could not restart $UNIT — check: journalctl -u $UNIT -e"
  fi

  # The GUI keeps running whatever it loaded at launch, so an upgraded package
  # plus a stale window is a real and confusing combination.
  if pgrep -f '/opt/maze-guard/main.py' >/dev/null 2>&1; then
    warn "A Maze Guard window is still running the previous build — quit it from"
    warn "the tray and relaunch to pick up ${VER:-the new version}."
  fi
}

command -v makepkg >/dev/null 2>&1 || die "makepkg not found — run this on Arch (pacman)."
[[ -f "$PKG_SRC/PKGBUILD" ]] || die "Missing $PKG_SRC/PKGBUILD"

# ── Read the version from the source of truth ─────────────────────────────────
VER="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/maze/__init__.py")"
[[ -n "$VER" ]] || die "Could not read __version__ from maze/__init__.py"
info "Building maze-guard ${VER} from working tree"

# ── Fresh build directory ─────────────────────────────────────────────────────
BUILD="$OUT/build"
rm -rf "$BUILD"
mkdir -p "$BUILD"

# ── Stage the source tree that goes into the tarball ──────────────────────────
# Only what package() consumes; __pycache__ / *.pyc are stripped so the tarball
# is reproducible and clean.
STAGE="$OUT/stage/maze-guard-${VER}"
rm -rf "$OUT/stage"
mkdir -p "$STAGE"
cp -r "$ROOT/maze" "$STAGE/"
find "$STAGE/maze" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$STAGE/maze" -name '*.pyc' -delete
for f in main.py pyproject.toml requirements.txt MAZE.png LICENSE; do
  [[ -f "$ROOT/$f" ]] && cp "$ROOT/$f" "$STAGE/" || warn "skipping missing $f"
done
# The polkit action is not optional: without it registered, the helper declines
# every protection-disabling request instead of doing it unauthenticated.
[[ -f "$PKG_SRC/org.mazeguard.policy" ]] \
  && cp "$PKG_SRC/org.mazeguard.policy" "$STAGE/" \
  || die "Missing $PKG_SRC/org.mazeguard.policy"

info "Creating source tarball"
tar czf "$BUILD/maze-guard-${VER}.tar.gz" -C "$OUT/stage" "maze-guard-${VER}"
rm -rf "$OUT/stage"

# ── Assemble the makepkg working dir ──────────────────────────────────────────
cp "$PKG_SRC/PKGBUILD" "$PKG_SRC/maze-guard.install" "$BUILD/"
# Pin pkgver to the version we just built (leaves packaging/PKGBUILD untouched).
sed -i "s/^pkgver=.*/pkgver=${VER}/" "$BUILD/PKGBUILD"

# ── Build ─────────────────────────────────────────────────────────────────────
info "Running makepkg ..."
( cd "$BUILD" && makepkg -f --noconfirm )

# ── Collect the artifact ──────────────────────────────────────────────────────
PKG="$(find "$BUILD" -maxdepth 1 -name '*.pkg.tar.zst' -print -quit)"
[[ -n "$PKG" ]] || die "makepkg finished but produced no .pkg.tar.zst"
mv -f "$PKG" "$OUT/"
FINAL="$OUT/$(basename "$PKG")"
# Keep the source tarball alongside the package for the AUR/mazelinux repo.
mv -f "$BUILD/maze-guard-${VER}.tar.gz" "$OUT/"
rm -rf "$BUILD"

ok "Package ready: $FINAL"
echo "    Source:  $OUT/maze-guard-${VER}.tar.gz"

if $DO_INSTALL; then
  info "Installing with pacman ..."
  sudo pacman -U --noconfirm "$FINAL"
  ok "Installed maze-guard ${VER}"
  if $DO_RESTART; then
    restart_daemon
  else
    warn "Daemon not restarted (--no-restart): the helper is still running the"
    warn "previous build.  sudo systemctl restart $UNIT"
  fi
else
  echo "    Install: sudo pacman -U \"$FINAL\""
  echo "    Then:    sudo systemctl restart $UNIT"
fi
