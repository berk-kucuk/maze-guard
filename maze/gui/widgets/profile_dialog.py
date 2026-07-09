"""Dialog to create or edit a custom security profile."""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QCheckBox, QPushButton, QFrame,
)
from PyQt6.QtCore import Qt
from maze.utils.config import CustomProfileConfig


class ProfileDialog(QDialog):
    """Returns a CustomProfileConfig via .result after exec()."""

    _FEATURES = [
        ("port_scan_detect",   "Port scan detection"),
        ("process_monitor",    "Unknown process monitoring"),
        ("mac_randomize",      "MAC address randomization"),
        ("hide_hostname",      "Hide hostname (disable mDNS)"),
        ("fingerprint_protect","TCP fingerprint protection"),
        ("block_incoming",     "Block unsolicited incoming connections"),
        ("block_services",     "Block mDNS/NetBIOS service leaks"),
        ("doh_enabled",        "DNS-over-HTTPS (leak prevention)"),
    ]

    def __init__(self, parent=None, existing: CustomProfileConfig = None):
        super().__init__(parent)
        self.setWindowTitle("Custom Profile" if not existing else f"Edit — {existing.name}")
        self.setFixedWidth(380)
        self.result_profile: CustomProfileConfig | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # Name
        root.addWidget(QLabel("Profile name:"))
        self._name = QLineEdit(existing.name if existing else "")
        self._name.setPlaceholderText("e.g. Office, Coffee Shop")
        root.addWidget(self._name)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        root.addWidget(sep)

        # Feature checkboxes
        self._checks: dict[str, QCheckBox] = {}
        for key, label in self._FEATURES:
            cb = QCheckBox(label)
            default = getattr(existing, key, key in ("port_scan_detect", "process_monitor"))
            cb.setChecked(bool(default))
            self._checks[key] = cb
            root.addWidget(cb)

        # Buttons
        btn_row = QHBoxLayout()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        btn_row.addWidget(cancel)
        btn_row.addStretch()
        save = QPushButton("Save Profile")
        save.setDefault(True)
        save.clicked.connect(self._save)
        btn_row.addWidget(save)
        root.addLayout(btn_row)

    def _save(self) -> None:
        name = self._name.text().strip()
        if not name:
            self._name.setPlaceholderText("Name is required!")
            return
        self.result_profile = CustomProfileConfig(
            name=name,
            **{key: self._checks[key].isChecked() for key, _ in self._FEATURES}
        )
        self.accept()
