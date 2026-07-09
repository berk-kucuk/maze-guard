import asyncio
import sys
import qasync
from PyQt6.QtWidgets import QApplication
from maze.gui.app_state import AppState
from maze.gui.dashboard import Dashboard
from maze.gui.privilege import connect_helper
from maze.gui.theme import get_stylesheet
from maze.core.engine import MazeEngine
from maze.gui.icons import create_app_icon
from maze.utils.config import load_config, save_config


# CLI flags that ask the app to start hidden in the tray (used by autostart).
_BACKGROUND_FLAGS = {"--background", "--tray", "--hidden", "--minimized"}


def _start_hidden(argv: list[str]) -> bool:
    return any(a in _BACKGROUND_FLAGS for a in argv)


def run() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Maze Guard")
    app.setApplicationDisplayName("Maze Guard")
    app.setOrganizationName("maze")
    app.setWindowIcon(create_app_icon(64))

    # Keep the event loop alive when the main window is hidden to the tray.
    app.setQuitOnLastWindowClosed(False)

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
        # Autostart / background launch: stay in the tray, don't pop the window.
        if not start_hidden:
            window.show()
        await engine.start()

    with loop:
        loop.run_until_complete(_boot())
        loop.run_forever()
