from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtCore import QObject
from maze.gui.icons import create_app_icon


class SystemTray(QObject):
    def __init__(self, on_show, on_quit):
        super().__init__()
        self._tray = QSystemTrayIcon()
        self._tray.setIcon(create_app_icon(64))
        self._tray.setToolTip("Maze Guard")

        menu = QMenu()
        menu.addAction("Show").triggered.connect(on_show)
        menu.addSeparator()
        menu.addAction("Quit").triggered.connect(on_quit)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_activate)
        self._on_show = on_show

    def show(self) -> None:
        self._tray.show()

    def notify_danger(self, title: str, message: str) -> None:
        self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Critical, 5000)

    def notify_warning(self, title: str, message: str) -> None:
        self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Warning, 4000)

    def _on_activate(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._on_show()
