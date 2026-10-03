from PyQt6.QtGui import QAction, QActionGroup
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtCore import QObject
from maze.gui.icons import create_app_icon


class SystemTray(QObject):
    def __init__(self, on_show, on_quit, on_notification_clicked=None):
        super().__init__()
        # What the last notification was about, so clicking it can open the
        # page that explains it. A notification that only says something
        # happened, with no way to reach it, makes people dismiss the next one.
        self._last_context = ""
        self._on_notification_clicked = on_notification_clicked
        self._on_show = on_show
        self._on_quit = on_quit
        self._tray = QSystemTrayIcon()
        self._tray.setIcon(create_app_icon(64))
        self._tray.setToolTip("Maze Guard")
        self._menu = QMenu()
        self._tray.setContextMenu(self._menu)
        self._tray.activated.connect(self._on_activate)
        self._tray.messageClicked.connect(self._on_message_clicked)
        self.build_menu()

    def build_menu(self, labels: dict | None = None, profiles: list[str] = (),
                   current: int = -1, on_profile=None) -> None:
        """(Re)build the context menu: open, a profile switcher, quit."""
        labels = labels or {}
        self._menu.clear()
        self._menu.addAction(labels.get("open", "Show")).triggered.connect(self._on_show)
        if profiles and on_profile:
            sub = self._menu.addMenu(labels.get("profile", "Profile"))
            group = QActionGroup(sub)
            group.setExclusive(True)
            for i, name in enumerate(profiles):
                act = QAction(name, sub)
                act.setCheckable(True)
                act.setChecked(i == current)
                act.triggered.connect(lambda _c, i=i: on_profile(i))
                group.addAction(act)
                sub.addAction(act)
        self._menu.addSeparator()
        self._menu.addAction(labels.get("quit", "Quit")).triggered.connect(self._on_quit)

    def set_tooltip(self, text: str) -> None:
        self._tray.setToolTip(text)

    def show(self) -> None:
        self._tray.show()

    def notify_danger(self, title: str, message: str, context: str = "threats") -> None:
        self._last_context = context
        self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Critical, 5000)

    def notify_warning(self, title: str, message: str, context: str = "events") -> None:
        self._last_context = context
        self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Warning, 4000)

    def _on_message_clicked(self) -> None:
        self._on_show()
        if self._on_notification_clicked:
            self._on_notification_clicked(self._last_context)

    def _on_activate(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._on_show()
