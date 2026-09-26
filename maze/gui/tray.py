from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtCore import QObject
from maze.gui.icons import create_app_icon


class SystemTray(QObject):
    def __init__(self, on_show, on_quit, on_notification_clicked=None):
        super().__init__()
        # What the last notification was about, so clicking it can open the
        # tab that explains it. A notification that only says something
        # happened, with no way to reach it, makes people dismiss the next one.
        self._last_context = ""
        self._on_notification_clicked = on_notification_clicked
        self._tray = QSystemTrayIcon()
        self._tray.setIcon(create_app_icon(64))
        self._tray.setToolTip("Maze Guard")

        menu = QMenu()
        menu.addAction("Show").triggered.connect(on_show)
        menu.addSeparator()
        menu.addAction("Quit").triggered.connect(on_quit)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_activate)
        self._tray.messageClicked.connect(self._on_message_clicked)
        self._on_show = on_show

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
