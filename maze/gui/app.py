import asyncio
import sys
import qasync
from PyQt6.QtWidgets import QApplication
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from maze.gui.app_state import AppState
from maze.gui.dashboard import Dashboard
from maze.gui.privilege import connect_helper
from maze.gui.theme import get_stylesheet
from maze.core.engine import MazeEngine
from maze.core.profile import Profile
from maze.gui.icons import create_app_icon
from maze.utils.config import load_config, save_config


# CLI flags that ask the app to start hidden in the tray (used by autostart).
_BACKGROUND_FLAGS = {"--background", "--tray", "--hidden", "--minimized"}

# Name of the local socket used to enforce a single running instance.
_SINGLETON_NAME = "maze-guard-singleton"


def _start_hidden(argv: list[str]) -> bool:
    return any(a in _BACKGROUND_FLAGS for a in argv)


def _activate_running_instance() -> bool:
    """If another instance already holds the singleton socket, ask it to show
    its window and return True. Otherwise return False (we are the first)."""
    sock = QLocalSocket()
    sock.connectToServer(_SINGLETON_NAME)
    if sock.waitForConnected(300):
        sock.write(b"show")
        sock.flush()
        sock.waitForBytesWritten(300)
        sock.disconnectFromServer()
        return True
    return False


def _resolve_startup_profile(cfg) -> Profile:
    """The profile to apply on launch. Persisted across restarts; defaults to
    HOME so passive detection and core protections are active out of the box
    instead of everything starting disabled."""
    try:
        return Profile(getattr(cfg, "profile", "home"))
    except ValueError:
        return Profile.HOME


def run() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Maze Guard")
    app.setApplicationDisplayName("Maze Guard")
    app.setOrganizationName("maze")
    # Tie the window to the installed maze-guard.desktop entry. This sets the
    # X11 WM_CLASS / Wayland app_id to "maze-guard" so the running window is
    # grouped under the app's own icon (matching StartupWMClass in the .desktop
    # file) instead of showing up in the dock as a generic "python3" window.
    app.setDesktopFileName("maze-guard")
    app.setWindowIcon(create_app_icon(64))

    # Keep the event loop alive when the main window is hidden to the tray.
    app.setQuitOnLastWindowClosed(False)

    # Single-instance guard: if Maze Guard is already running (e.g. hidden in
    # the tray from autostart), just surface its window and exit instead of
    # spawning a second GUI + tray icon.
    if _activate_running_instance():
        return

    # We are the primary instance — claim the singleton socket. removeServer
    # clears a stale socket left behind by a previous crash.
    QLocalServer.removeServer(_SINGLETON_NAME)
    singleton_server = QLocalServer()
    singleton_server.listen(_SINGLETON_NAME)

    cfg = load_config()
    start_hidden = _start_hidden(sys.argv)

    state = AppState(theme=cfg.theme, language=cfg.language)
    app.setStyleSheet(get_stylesheet(state.theme))
    state.theme_changed.connect(lambda t: app.setStyleSheet(get_stylesheet(t)))

    def _save_theme(t: str) -> None:
        cfg.theme = t
        save_config(cfg)

    def _save_language(l: str) -> None:
        cfg.language = l
        save_config(cfg)

    state.theme_changed.connect(_save_theme)
    state.language_changed.connect(_save_language)

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    async def _boot():
        # Connect to the privileged helper daemon. No password prompt: if the
        # daemon is running the GUI gets full functionality, otherwise it runs
        # in limited (detection-only) mode.
        helper = await connect_helper(cfg.interface)

        engine = MazeEngine(cfg, helper=helper)
        window = Dashboard(engine, cfg, state)

        # When a second launch pings the singleton socket, surface this window.
        def _on_second_instance() -> None:
            conn = singleton_server.nextPendingConnection()
            if conn is not None:
                conn.disconnectFromServer()
            window.showNormal()
            window.raise_()
            window.activateWindow()

        singleton_server.newConnection.connect(_on_second_instance)

        # Autostart / background launch: stay in the tray, don't pop the window.
        if not start_hidden:
            window.show()
        await engine.start()

        # Apply the startup profile so core protections run out of the box
        # rather than everything starting disabled (MANUAL).
        engine.profiles.set(_resolve_startup_profile(cfg))

    with loop:
        loop.run_until_complete(_boot())
        loop.run_forever()
