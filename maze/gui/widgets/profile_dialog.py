"""Dialog to create or edit a custom security profile."""
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFrame, QLabel, QLineEdit, QVBoxLayout,
)

from maze.utils.config import CustomProfileConfig

# Feature flags in the order they are offered; labels are "pf_<flag>".
_FEATURES = ("port_scan_detect", "process_monitor", "doh_enabled",
             "block_incoming", "hide_hostname", "fingerprint_protect",
             "block_services")


class ProfileDialog(QDialog):
    """Sets ``result_profile`` to a CustomProfileConfig when accepted."""

    def __init__(self, state, parent=None, existing: CustomProfileConfig = None,
                 taken: set | None = None):
        super().__init__(parent)
        s = state.t
        self._s = s
        self._taken = {n.lower() for n in (taken or set())}
        self.setWindowTitle(s("pf_title_edit") if existing else s("pf_title_new"))
        self.setMinimumWidth(420)
        self.result_profile: CustomProfileConfig | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 18)
        root.setSpacing(12)

        root.addWidget(QLabel(s("pf_name")))
        self._name = QLineEdit(existing.name if existing else "")
        self._name.setPlaceholderText(s("pf_name_placeholder"))
        root.addWidget(self._name)
        self._error = QLabel("")
        self._error.setStyleSheet("color: #ff4d2e;")
        self._error.setVisible(False)
        root.addWidget(self._error)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        root.addWidget(sep)

        note = QLabel(s("pf_note"))
        note.setObjectName("muted")
        note.setWordWrap(True)
        root.addWidget(note)

        self._checks: dict[str, QCheckBox] = {}
        for key in _FEATURES:
            cb = QCheckBox(s(f"pf_{key}"))
            default = getattr(existing, key, key in ("port_scan_detect", "process_monitor"))
            cb.setChecked(bool(default))
            self._checks[key] = cb
            root.addWidget(cb)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText(s("pf_save"))
        buttons.button(QDialogButtonBox.StandardButton.Save).setObjectName("primary")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(s("pf_cancel"))
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _fail(self, text: str) -> None:
        self._error.setText(text)
        self._error.setVisible(True)

    def _save(self) -> None:
        name = self._name.text().strip()
        if not name:
            self._fail(self._s("pf_name_required"))
            return
        if name.lower() in self._taken:
            self._fail(self._s("pf_name_taken"))
            return
        self.result_profile = CustomProfileConfig(
            name=name, **{key: cb.isChecked() for key, cb in self._checks.items()})
        self.accept()
