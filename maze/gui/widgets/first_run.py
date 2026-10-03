"""
The first launch.

A security tool that opens on an eight-tab dashboard has told a new user
nothing about what it is doing on their behalf. Four questions, asked once,
settle everything that cannot be inferred: which link to watch, whether this
network is one they trust, whether to defend automatically, and whether to be
here after the next reboot.

Every answer has a working default, the dialog can be dismissed, and it never
blocks startup — if anything here fails, the application opens as before.
"""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QCheckBox,
    QDialogButtonBox, QFrame,
)

from maze.gui import autostart
from maze.utils.logger import log
from maze.utils.network_info import current_network_id


class FirstRunDialog(QDialog):
    def __init__(self, state, cfg, interfaces, parent=None):
        super().__init__(parent)
        self._state = state
        self._cfg = cfg
        self.setWindowTitle("Maze Guard")
        self.setMinimumWidth(470)

        # Asked synchronously: this is a modal on a cold start, the lookup is
        # bounded to a couple of seconds, and the answer decides what the
        # "trust this network" line can even say.
        try:
            self._network_id = current_network_id(cfg.interface or "")
        except Exception:
            self._network_id = ""

        s = state.t
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 18)
        layout.setSpacing(12)

        title = QLabel(s("fr_title"))
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        intro = QLabel(s("fr_intro"))
        intro.setWordWrap(True)
        intro.setObjectName("muted")
        layout.addWidget(intro)
        layout.addWidget(_separator())

        row = QHBoxLayout()
        row.addWidget(QLabel(s("fr_interface")))
        self._iface = QComboBox()
        for name in interfaces or [cfg.interface]:
            if name:
                self._iface.addItem(name)
        if cfg.interface and self._iface.findText(cfg.interface) >= 0:
            self._iface.setCurrentText(cfg.interface)
        row.addWidget(self._iface, 1)
        layout.addLayout(row)

        kind, _, value = self._network_id.partition(":")
        shown = (value if kind == "wifi"
                 else f'{s("dash_wired")} ({value})' if kind == "gw"
                 else self._network_id or s("fr_no_network"))
        self._trust = QCheckBox(s("fr_trust").format(network=shown))
        self._trust.setEnabled(bool(self._network_id))
        self._trust.setChecked(bool(self._network_id))
        layout.addWidget(self._trust)

        self._auto_block = QCheckBox(s("fr_auto_block"))
        self._auto_block.setChecked(bool(getattr(cfg, "auto_block", True)))
        layout.addWidget(self._auto_block)

        self._autostart = QCheckBox(s("fr_autostart"))
        self._autostart.setChecked(autostart.is_enabled())
        if autostart.is_system_wide():
            self._autostart.setEnabled(False)
            self._autostart.setToolTip(s("fr_autostart_system"))
        layout.addWidget(self._autostart)

        note = QLabel(s("fr_note"))
        note.setWordWrap(True)
        note.setObjectName("muted")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(s("fr_start"))
        buttons.button(QDialogButtonBox.StandardButton.Ok).setObjectName("primary")
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def apply(self) -> None:
        """Write the answers into the config. The caller persists it."""
        cfg = self._cfg
        chosen = self._iface.currentText().strip()
        if chosen:
            cfg.interface = chosen
        cfg.auto_block = self._auto_block.isChecked()
        if self._trust.isChecked() and self._network_id:
            if self._network_id not in cfg.trusted_networks:
                cfg.trusted_networks.append(self._network_id)
        if self._autostart.isEnabled():
            try:
                autostart.enable() if self._autostart.isChecked() else autostart.disable()
            except OSError as exc:
                log.warning(f"could not write the autostart entry: {exc}")
        cfg.first_run_done = True


def _separator() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    return line
