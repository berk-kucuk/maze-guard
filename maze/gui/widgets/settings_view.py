"""Settings tab — threshold, rotation, known processes, whitelisted IPs, autostart."""
import asyncio
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QCheckBox,
    QSpinBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLineEdit, QScrollArea, QFrame, QSizePolicy, QComboBox,
)
from PyQt6.QtCore import Qt
import re

_AUTOSTART_PATH = Path.home() / ".config" / "autostart" / "maze.desktop"
# A system-wide install (install.sh) drops this one; the settings checkbox must
# reflect it too, otherwise it shows "off" while the app still autostarts.
_SYS_AUTOSTART_PATH = Path("/etc/xdg/autostart/maze-guard.desktop")
_AUTOSTART_TEMPLATE = """\
[Desktop Entry]
Type=Application
Name=Maze Guard
Exec={python} {script} --background
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')


class SettingsView(QWidget):
    def __init__(self, state, engine, cfg, save_cb, on_auto_profile_change=None):
        """
        save_cb: callable() — called after any setting change to persist config
        on_auto_profile_change: callable() — called after the auto-profile toggle
            or trusted-networks list changes, so the watcher can reconfigure.
        """
        super().__init__()
        self._state   = state
        self._engine  = engine
        self._cfg     = cfg
        self._save_cb = save_cb
        self._on_auto_profile_change = on_auto_profile_change or (lambda: None)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(20)

        layout.addWidget(self._build_general_group())
        layout.addWidget(self._build_auto_profile_group())
        layout.addWidget(self._build_processes_group())
        layout.addWidget(self._build_whitelist_group())
        layout.addWidget(self._build_system_group())
        layout.addStretch()

        scroll.setWidget(inner)
        root.addWidget(scroll)

    # ── General ────────────────────────────────────────────────────────────

    def _build_general_group(self) -> QGroupBox:
        grp = QGroupBox("General")
        layout = QVBoxLayout(grp)
        layout.setSpacing(12)

        # Port scan threshold
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Port scan threshold (SYN count):"))
        self._threshold_spin = QSpinBox()
        self._threshold_spin.setRange(3, 500)
        self._threshold_spin.setValue(self._cfg.port_scan_threshold)
        self._threshold_spin.setFixedWidth(90)
        self._threshold_spin.valueChanged.connect(self._on_threshold_change)
        row1.addWidget(self._threshold_spin)
        row1.addStretch()
        layout.addLayout(row1)

        # Desktop notification threshold. Events always reach the dashboard list;
        # this only decides which of them are allowed to pop up a tray message.
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Desktop notifications:"))
        self._notify_combo = QComboBox()
        for label, value in self._NOTIFY_CHOICES:
            self._notify_combo.addItem(label, value)
        current = str(getattr(self._cfg, "notify_min_level", "dangerous")).lower()
        idx = self._notify_combo.findData(current)
        self._notify_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._notify_combo.setFixedWidth(220)
        self._notify_combo.currentIndexChanged.connect(self._on_notify_level_change)
        row3.addWidget(self._notify_combo)
        row3.addStretch()
        layout.addLayout(row3)

        # Automatic blocking. Only ever applies to a confirmed active attack
        # (port scan, stealth scan, correlated multi-stage) from an on-link
        # private address, and never to gateway/DNS infrastructure — but it is
        # still the app acting on its own, so it is switchable.
        self._auto_block_cb = QCheckBox(
            "Automatically block confirmed attackers")
        self._auto_block_cb.setChecked(bool(getattr(self._cfg, "auto_block", True)))
        self._auto_block_cb.setToolTip(
            "When a source is caught scanning this host, add a firewall drop "
            "rule for it after reconnaissance.\n"
            "Gateway, DNS and whitelisted addresses are never blocked, and "
            "public (spoofable) sources are ignored.")
        self._auto_block_cb.toggled.connect(self._on_auto_block_toggle)
        layout.addWidget(self._auto_block_cb)

        return grp

    def _on_auto_block_toggle(self, enabled: bool) -> None:
        self._cfg.auto_block = enabled
        self._save_cb()

    # (label, stored value) — order matters: index 0 is the fallback.
    _NOTIFY_CHOICES = (
        ("Dangerous only (recommended)", "dangerous"),
        ("Dangerous + suspicious", "suspicious"),
        ("Off — dashboard only", "off"),
    )

    def _on_notify_level_change(self, _idx: int) -> None:
        self._cfg.notify_min_level = self._notify_combo.currentData()
        self._save_cb()

    def _on_threshold_change(self, val: int) -> None:
        self._cfg.port_scan_threshold = val
        scanner = self._engine._modules.get("port_scan")
        if scanner:
            scanner.threshold = val
        self._save_cb()

    # ── Auto profile ───────────────────────────────────────────────────────

    def _build_auto_profile_group(self) -> QGroupBox:
        grp = QGroupBox("Automatic Profile Switching")
        layout = QVBoxLayout(grp)
        layout.setSpacing(8)

        self._auto_cb = QCheckBox(
            "Switch to Public on unknown networks, Home on trusted ones")
        self._auto_cb.setChecked(bool(self._cfg.auto_profile_switch))
        self._auto_cb.toggled.connect(self._on_auto_toggle)
        layout.addWidget(self._auto_cb)

        row = QHBoxLayout()
        self._trust_btn = QPushButton("Trust current network")
        self._trust_btn.clicked.connect(self._trust_current_network)
        row.addWidget(self._trust_btn)
        self._trust_status = QLabel("")
        self._trust_status.setStyleSheet("font-size: 11px; color: #888;")
        row.addWidget(self._trust_status)
        row.addStretch()
        layout.addLayout(row)

        self._trusted_table = QTableWidget(0, 2)
        self._trusted_table.setHorizontalHeaderLabels(["Trusted network", "Remove"])
        self._trusted_table.verticalHeader().setVisible(False)
        self._trusted_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._trusted_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._trusted_table.setColumnWidth(1, 80)
        self._trusted_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._trusted_table.setMaximumHeight(150)
        layout.addWidget(self._trusted_table)

        self._populate_trusted()
        return grp

    def _on_auto_toggle(self, enabled: bool) -> None:
        self._cfg.auto_profile_switch = enabled
        self._save_cb()
        self._on_auto_profile_change()

    def _trust_current_network(self) -> None:
        from maze.utils.network_info import current_network_id
        net_id = current_network_id(self._cfg.interface)
        if not net_id:
            self._trust_status.setText("No network detected")
            return
        if net_id not in self._cfg.trusted_networks:
            self._cfg.trusted_networks.append(net_id)
            self._save_cb()
            self._on_auto_profile_change()
            self._populate_trusted()
        self._trust_status.setText(f"Trusted: {net_id}")

    def _populate_trusted(self) -> None:
        self._trusted_table.setRowCount(0)
        for net_id in self._cfg.trusted_networks:
            row = self._trusted_table.rowCount()
            self._trusted_table.insertRow(row)
            self._trusted_table.setItem(row, 0, QTableWidgetItem(net_id))
            btn = QPushButton("Remove")
            btn.setFixedHeight(24)
            btn.setStyleSheet("font-size: 11px;")
            btn.clicked.connect(lambda _, n=net_id: self._remove_trusted(n))
            self._trusted_table.setCellWidget(row, 1, btn)

    def _remove_trusted(self, net_id: str) -> None:
        if net_id in self._cfg.trusted_networks:
            self._cfg.trusted_networks.remove(net_id)
            self._save_cb()
            self._on_auto_profile_change()
        self._populate_trusted()

    # ── Known Processes ────────────────────────────────────────────────────

    def _build_processes_group(self) -> QGroupBox:
        grp = QGroupBox("Known Processes (never flagged)")
        layout = QVBoxLayout(grp)
        layout.setSpacing(8)

        self._proc_table = QTableWidget(0, 2)
        self._proc_table.setHorizontalHeaderLabels(["Process Name", "Remove"])
        self._proc_table.verticalHeader().setVisible(False)
        self._proc_table.horizontalHeader().setStretchLastSection(False)
        self._proc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._proc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._proc_table.setColumnWidth(1, 80)
        self._proc_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._proc_table.setMaximumHeight(200)
        layout.addWidget(self._proc_table)

        add_row = QHBoxLayout()
        self._proc_input = QLineEdit()
        self._proc_input.setPlaceholderText("Process name (e.g. vlc)")
        self._proc_input.returnPressed.connect(self._add_process)
        add_row.addWidget(self._proc_input)
        btn = QPushButton("Add")
        btn.setFixedWidth(70)
        btn.clicked.connect(self._add_process)
        add_row.addWidget(btn)
        layout.addLayout(add_row)

        self._populate_processes()
        return grp

    def _populate_processes(self) -> None:
        self._proc_table.setRowCount(0)
        for name in sorted(self._cfg.known_processes):
            self._add_proc_row(name)

    def _add_proc_row(self, name: str) -> None:
        row = self._proc_table.rowCount()
        self._proc_table.insertRow(row)
        self._proc_table.setItem(row, 0, QTableWidgetItem(name))
        btn = QPushButton("Remove")
        btn.setFixedHeight(24)
        btn.setStyleSheet("font-size: 11px;")
        btn.clicked.connect(lambda _, n=name: self._remove_process(n))
        self._proc_table.setCellWidget(row, 1, btn)

    def _add_process(self) -> None:
        name = self._proc_input.text().strip()
        if not name or name in self._cfg.known_processes:
            return
        self._proc_input.clear()
        self._cfg.known_processes.append(name)
        pm = self._engine._modules.get("process")
        if pm:
            pm._known.add(name)
        self._save_cb()
        self._add_proc_row(name)

    def _remove_process(self, name: str) -> None:
        if name in self._cfg.known_processes:
            self._cfg.known_processes.remove(name)
        pm = self._engine._modules.get("process")
        if pm:
            pm._known.discard(name)
        self._save_cb()
        self._populate_processes()

    # ── IP Whitelist ───────────────────────────────────────────────────────

    def _build_whitelist_group(self) -> QGroupBox:
        grp = QGroupBox("Whitelisted IPs (ignored by all detectors)")
        layout = QVBoxLayout(grp)
        layout.setSpacing(8)

        self._wl_table = QTableWidget(0, 2)
        self._wl_table.setHorizontalHeaderLabels(["IP / CIDR", "Remove"])
        self._wl_table.verticalHeader().setVisible(False)
        self._wl_table.horizontalHeader().setStretchLastSection(False)
        self._wl_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._wl_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._wl_table.setColumnWidth(1, 80)
        self._wl_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._wl_table.setMaximumHeight(180)
        layout.addWidget(self._wl_table)

        add_row = QHBoxLayout()
        self._wl_input = QLineEdit()
        self._wl_input.setPlaceholderText("e.g. 192.168.0.1 or 10.0.0.0/8")
        self._wl_input.returnPressed.connect(self._add_whitelist)
        add_row.addWidget(self._wl_input)
        btn = QPushButton("Add")
        btn.setFixedWidth(70)
        btn.clicked.connect(self._add_whitelist)
        add_row.addWidget(btn)
        layout.addLayout(add_row)

        self._populate_whitelist()
        return grp

    def _populate_whitelist(self) -> None:
        self._wl_table.setRowCount(0)
        for ip in self._cfg.whitelist_ips:
            self._add_wl_row(ip)

    def _add_wl_row(self, ip: str) -> None:
        row = self._wl_table.rowCount()
        self._wl_table.insertRow(row)
        self._wl_table.setItem(row, 0, QTableWidgetItem(ip))
        btn = QPushButton("Remove")
        btn.setFixedHeight(24)
        btn.setStyleSheet("font-size: 11px;")
        btn.clicked.connect(lambda _, i=ip: self._remove_whitelist(i))
        self._wl_table.setCellWidget(row, 1, btn)

    def _add_whitelist(self) -> None:
        ip = self._wl_input.text().strip()
        if not ip or not _IP_RE.match(ip) or ip in self._cfg.whitelist_ips:
            return
        self._wl_input.clear()
        self._cfg.whitelist_ips.append(ip)
        self._save_cb()
        self._add_wl_row(ip)

    def _remove_whitelist(self, ip: str) -> None:
        if ip in self._cfg.whitelist_ips:
            self._cfg.whitelist_ips.remove(ip)
        self._save_cb()
        self._populate_whitelist()

    # ── System ─────────────────────────────────────────────────────────────

    def _build_system_group(self) -> QGroupBox:
        grp = QGroupBox("System")
        layout = QVBoxLayout(grp)
        layout.setSpacing(10)

        self._autostart_cb = QCheckBox("Launch Maze Guard automatically on login (hidden in tray)")
        self._autostart_cb.setChecked(_AUTOSTART_PATH.exists() or _SYS_AUTOSTART_PATH.exists())
        self._autostart_cb.toggled.connect(self._toggle_autostart)
        layout.addWidget(self._autostart_cb)

        self._autostart_note = QLabel(f"Writes to {_AUTOSTART_PATH}")
        self._autostart_note.setStyleSheet("font-size: 11px; color: #888;")
        layout.addWidget(self._autostart_note)

        return grp

    def _toggle_autostart(self, enabled: bool) -> None:
        if enabled:
            _AUTOSTART_PATH.parent.mkdir(parents=True, exist_ok=True)
            # Find main.py from the package location
            script = str(
                Path(sys.modules["maze"].__file__).parent.parent / "main.py"
            )
            _AUTOSTART_PATH.write_text(
                _AUTOSTART_TEMPLATE.format(
                    python=sys.executable,
                    script=script,
                )
            )
            self._autostart_note.setText(f"Writes to {_AUTOSTART_PATH}")
        else:
            _AUTOSTART_PATH.unlink(missing_ok=True)
            # A system-wide autostart entry can only be removed with root; warn
            # rather than silently leaving the app to keep launching on login.
            if _SYS_AUTOSTART_PATH.exists():
                self._autostart_note.setText(
                    f"System-wide autostart still active at {_SYS_AUTOSTART_PATH} "
                    f"— remove it with: sudo rm {_SYS_AUTOSTART_PATH}"
                )
                self._autostart_note.setStyleSheet("font-size: 11px; color: #e0a050;")
