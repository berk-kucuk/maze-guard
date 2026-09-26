#!/usr/bin/env bash
# =============================================================================
#  Maze Guard — everything that has to be true before a release.
#
#  One command, no CI service required:
#
#    ./scripts/check.sh            tests + static checks
#    ./scripts/check.sh --package  the above, then build the Arch package
#    ./scripts/check.sh --quick    skip the end-to-end namespace test
#
#  Exit code is non-zero if any stage fails, so it can be wired into a git
#  hook or whatever runner you like.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PY:-$ROOT/venv/bin/python}"
[[ -x "$PY" ]] || PY="$(command -v python3)"

if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; DIM='\033[2m'; RESET='\033[0m'
else
  GREEN=''; RED=''; BLUE=''; DIM=''; RESET=''
fi

FAILED=()
stage() { echo -e "\n${BLUE}══${RESET} $* ${DIM}$(printf '─%.0s' {1..30})${RESET}"; }
check() {
  local name="$1"; shift
  if "$@"; then
    echo -e "${GREEN}✓${RESET} $name"
  else
    echo -e "${RED}✗${RESET} $name"
    FAILED+=("$name")
  fi
}

QUICK=false
PACKAGE=false
for arg in "$@"; do
  case "$arg" in
    --quick)   QUICK=true ;;
    --package) PACKAGE=true ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

stage "Syntax"
check "every module compiles" "$PY" -m compileall -q maze main.py tests

stage "Tests"
if $QUICK; then
  # Everything except the namespace end-to-end run, which costs a few seconds.
  check "unit tests" env MAZE_SKIP_INTEGRATION=1 "$PY" -m unittest discover -s tests -p 'test_*.py' -q
else
  check "unit + end-to-end tests" "$PY" -m unittest discover -s tests -q
fi

stage "Consistency"
check "versions agree across pyproject, package and __init__" "$PY" - <<'PYEOF'
import re, sys, pathlib
root = pathlib.Path(".")
def grab(path, pattern):
    m = re.search(pattern, (root / path).read_text(), re.M)
    return m.group(1) if m else None
versions = {
    "maze/__init__.py": grab("maze/__init__.py", r'__version__ = "([^"]+)"'),
    "pyproject.toml":   grab("pyproject.toml", r'^version = "([^"]+)"'),
    "packaging/PKGBUILD": grab("packaging/PKGBUILD", r'^pkgver=(\S+)'),
}
if len(set(versions.values())) != 1 or None in versions.values():
    for k, v in versions.items():
        print(f"  {k}: {v}")
    sys.exit(1)
print(f"  all at {next(iter(versions.values()))}")
PYEOF

check "no leftover debug statements" bash -c '
  ! grep -rn "breakpoint()\|import pdb\|print(\"DEBUG" --include="*.py" maze/ '

stage "Privileged surface"
check "helper accepts only drop rules" "$PY" - <<'PYEOF'
import importlib.util, sys, pathlib
spec = importlib.util.spec_from_file_location(
    "helper_check", pathlib.Path("maze/helper.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
bad = [r.pattern for r in mod._FWC_RULE_RES if "drop$" not in r.pattern]
forbidden = {"--set-default-zone", "--direct", "--panic-on", "--add-service"}
leaked = forbidden & set(mod._FWC_SAFE_FLAGS)
if bad or leaked:
    print(f"  rules not ending in drop: {bad}")
    print(f"  dangerous flags allowed:  {leaked}")
    sys.exit(1)
print(f"  {len(mod._FWC_RULE_RES)} rule forms, all drop-only; "
      f"{len(mod._FWC_SAFE_FLAGS)} flags allowed")
PYEOF

if $PACKAGE; then
  stage "Package"
  check "arch package builds" ./build-pkg.sh
fi

echo
if ((${#FAILED[@]})); then
  echo -e "${RED}FAILED:${RESET} ${FAILED[*]}"
  exit 1
fi
echo -e "${GREEN}All checks passed.${RESET}"
