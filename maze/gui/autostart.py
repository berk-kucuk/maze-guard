"""
Start-on-login, in one place.

Two entries can make this application start with the session: one written per
user by the Settings toggle, and one installed system-wide by the package. The
checkbox has to reflect both — a toggle that reads only its own file shows
"off" while the application keeps launching, which is the kind of small lie
that makes people distrust the rest of the interface.
"""
import sys
from pathlib import Path

USER_PATH = Path.home() / ".config" / "autostart" / "maze.desktop"
SYSTEM_PATH = Path("/etc/xdg/autostart/maze-guard.desktop")

_TEMPLATE = """\
[Desktop Entry]
Type=Application
Name=Maze Guard
Exec={python} {script} --background
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""


def _script_path() -> str:
    return str(Path(sys.modules["maze"].__file__).parent.parent / "main.py")


def is_enabled() -> bool:
    """Whether anything will start this application at login."""
    return USER_PATH.exists() or SYSTEM_PATH.exists()


def is_system_wide() -> bool:
    """True when the package's entry is present. It cannot be removed without
    root, so the UI has to say so rather than pretending the toggle worked."""
    return SYSTEM_PATH.exists()


def enable() -> Path:
    USER_PATH.parent.mkdir(parents=True, exist_ok=True)
    USER_PATH.write_text(_TEMPLATE.format(python=sys.executable,
                                          script=_script_path()))
    return USER_PATH


def disable() -> None:
    USER_PATH.unlink(missing_ok=True)
