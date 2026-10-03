"""Settings page — everything the user can change, grouped by what it affects."""
import ipaddress

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton,
    QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)

import maze
from maze.gui import autostart
from maze.utils.config import CONFIG_PATH


def _valid_address(text: str) -> bool:
    """An IPv4/IPv6 address or network, as the detectors will match it."""
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
        else:
            ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class _EditableList(QWidget):
    """A list with an add field, a remove button and an optional filter."""

    def __init__(self, on_add, on_remove, filterable: bool = False, height: int = 170):
        super().__init__()
        self._on_add = on_add
        self._on_remove = on_remove
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.filter = QLineEdit()
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self._apply_filter)
        self.filter.setVisible(filterable)
        lay.addWidget(self.filter)
        self.list = QListWidget()
        self.list.setFixedHeight(height)
        self.list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        lay.addWidget(self.list)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.input = QLineEdit()
        self.input.returnPressed.connect(self._add)
        row.addWidget(self.input, 1)
        self.add_btn = QPushButton()
        self.add_btn.clicked.connect(self._add)
        row.addWidget(self.add_btn)
        self.remove_btn = QPushButton()
        self.remove_btn.setObjectName("danger")
        self.remove_btn.clicked.connect(self._remove)
        self.remove_btn.setEnabled(False)
        self.list.itemSelectionChanged.connect(
            lambda: self.remove_btn.setEnabled(bool(self.list.selectedItems())))
        row.addWidget(self.remove_btn)
        lay.addLayout(row)

    def set_items(self, items) -> None:
        self.list.clear()
        for text in items:
            self.list.addItem(QListWidgetItem(text))
        self._apply_filter()

    def _apply_filter(self, *_):
        needle = self.filter.text().strip().lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(bool(needle) and needle not in item.text().lower())

    def _add(self) -> None:
        text = self.input.text().strip()
        if text and self._on_add(text):
            self.input.clear()

    def _remove(self) -> None:
        for item in self.list.selectedItems():
            self._on_remove(item.text())


class SettingsView(QWidget):
    def __init__(self, state, engine, cfg, save_cb, on_auto_profile_change=None,
                 on_profiles_change=None):
        """
        save_cb: callable() — called after any setting change to persist config
        on_auto_profile_change: callable() — after the auto-profile toggle or
            the trusted-networks list changes, so the watcher can reconfigure.
        on_profiles_change: callable() — after a custom profile is added or
            removed, so the profile selector can be rebuilt.
        """
        super().__init__()
        self._state   = state
        self._engine  = engine
        self._cfg     = cfg
        self._save_cb = save_cb
        self._on_auto_profile_change = on_auto_profile_change or (lambda: None)
        self._on_profiles_change = on_profiles_change or (lambda: None)
        self._build_ui()
        state.language_changed.connect(self.retranslate)
        state.theme_changed.connect(lambda _t: self._sync_appearance())
        self.retranslate()

    def _save(self) -> None:
        self._save_cb()

    # ── layout ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        self._layout = QVBoxLayout(inner)
        self._layout.setContentsMargins(24, 8, 24, 24)
        self._layout.setSpacing(4)

        # Two columns: settings people change, then the lists.
        cols = QHBoxLayout()
        cols.setSpacing(16)
        left = QVBoxLayout()
        left.setSpacing(4)
        right = QVBoxLayout()
        right.setSpacing(4)
        left.addWidget(self._build_appearance())
        left.addWidget(self._build_response())
        left.addWidget(self._build_profiles())
        left.addWidget(self._build_system())
        left.addStretch()
        right.addWidget(self._build_auto_profile())
        right.addWidget(self._build_whitelist())
        right.addWidget(self._build_processes())
        right.addStretch()
        cols.addLayout(left, 1)
        cols.addLayout(right, 1)
        self._layout.addLayout(cols)

        scroll.setWidget(inner)
        root.addWidget(scroll)

    @staticmethod
    def _hint() -> QLabel:
        lbl = QLabel()
        lbl.setObjectName("muted")
        lbl.setWordWrap(True)
        return lbl

    @staticmethod
    def _form(grp: QGroupBox) -> QFormLayout:
        form = QFormLayout(grp)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        return form

    # ── appearance ────────────────────────────────────────────────────────

    def _build_appearance(self) -> QGroupBox:
        self._grp_appearance = grp = QGroupBox()
        form = self._form(grp)
        self._lang = QComboBox()
        self._lang.addItem("English", "en")
        self._lang.addItem("Türkçe", "tr")
        self._lang.currentIndexChanged.connect(
            lambda _i: self._state.set_language(self._lang.currentData()))
        self._theme = QComboBox()
        self._theme.addItem("", "dark")
        self._theme.addItem("", "light")
        self._theme.currentIndexChanged.connect(
            lambda _i: self._state.set_theme(self._theme.currentData()))
        self._lbl_lang, self._lbl_theme = QLabel(), QLabel()
        form.addRow(self._lbl_lang, self._lang)
        form.addRow(self._lbl_theme, self._theme)
        self._sync_appearance()
        return grp

    def _sync_appearance(self) -> None:
        for combo, value in ((self._lang, self._state.language),
                             (self._theme, self._state.theme)):
            combo.blockSignals(True)
            idx = combo.findData(value)
            combo.setCurrentIndex(max(idx, 0))
            combo.blockSignals(False)

    # ── alerts and response ───────────────────────────────────────────────

    _NOTIFY_CHOICES = ("dangerous", "suspicious", "off")

    def _build_response(self) -> QGroupBox:
        self._grp_response = grp = QGroupBox()
        form = self._form(grp)

        self._notify_combo = QComboBox()
        for value in self._NOTIFY_CHOICES:
            self._notify_combo.addItem("", value)
        idx = self._notify_combo.findData(
            str(getattr(self._cfg, "notify_min_level", "dangerous")).lower())
        self._notify_combo.setCurrentIndex(max(idx, 0))
        self._notify_combo.currentIndexChanged.connect(self._on_notify_level_change)
        self._lbl_notify = QLabel()
        form.addRow(self._lbl_notify, self._notify_combo)

        self._threshold_spin = QSpinBox()
        self._threshold_spin.setRange(3, 500)
        self._threshold_spin.setValue(self._cfg.port_scan_threshold)
        self._threshold_spin.setMaximumWidth(110)
        self._threshold_spin.valueChanged.connect(self._on_threshold_change)
        self._lbl_threshold = QLabel()
        form.addRow(self._lbl_threshold, self._threshold_spin)

        self._newdev_cb = QCheckBox()
        self._newdev_cb.setChecked(bool(getattr(self._cfg, "notify_new_devices", True)))
        self._newdev_cb.toggled.connect(lambda v: self._set("notify_new_devices", v))
        form.addRow(self._newdev_cb)

        # Automatic blocking only ever applies to a confirmed active attack
        # from an on-link private address, never to gateway/DNS — but it is
        # still the app acting on its own, so it is switchable.
        self._auto_block_cb = QCheckBox()
        self._auto_block_cb.setChecked(bool(getattr(self._cfg, "auto_block", True)))
        self._auto_block_cb.toggled.connect(lambda v: self._set("auto_block", v))
        form.addRow(self._auto_block_cb)

        self._mac_block_cb = QCheckBox()
        self._mac_block_cb.setChecked(bool(getattr(self._cfg, "block_by_mac", True)))
        self._mac_block_cb.toggled.connect(lambda v: self._set("block_by_mac", v))
        form.addRow(self._mac_block_cb)
        return grp

    def _set(self, attr: str, value) -> None:
        setattr(self._cfg, attr, value)
        self._save()

    def _on_notify_level_change(self, _idx: int) -> None:
        self._set("notify_min_level", self._notify_combo.currentData())

    def _on_threshold_change(self, val: int) -> None:
        self._cfg.port_scan_threshold = val
        scanner = self._engine._modules.get("port_scan")
        if scanner:
            scanner.threshold = val
        self._save()

    # ── custom profiles ───────────────────────────────────────────────────

    def _build_profiles(self) -> QGroupBox:
        self._grp_profiles = grp = QGroupBox()
        lay = QVBoxLayout(grp)
        lay.setSpacing(10)
        self._profiles_hint = self._hint()
        lay.addWidget(self._profiles_hint)
        self._profiles_list = QListWidget()
        self._profiles_list.setFixedHeight(110)
        self._profiles_list.itemDoubleClicked.connect(lambda _i: self._edit_profile())
        lay.addWidget(self._profiles_list)
        row = QHBoxLayout()
        self._btn_new_profile = QPushButton()
        self._btn_new_profile.setObjectName("primary")
        self._btn_new_profile.clicked.connect(self._new_profile)
        self._btn_edit_profile = QPushButton()
        self._btn_edit_profile.clicked.connect(self._edit_profile)
        self._btn_del_profile = QPushButton()
        self._btn_del_profile.setObjectName("danger")
        self._btn_del_profile.clicked.connect(self._delete_profile)
        for b in (self._btn_new_profile, self._btn_edit_profile, self._btn_del_profile):
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        self._profiles_list.itemSelectionChanged.connect(self._sync_profile_buttons)
        return grp

    def _populate_profiles(self) -> None:
        s = self._state
        self._profiles_list.clear()
        for p in self._cfg.custom_profiles:
            flags = [s.t(f"pf_{k}") for k in ("hide_hostname", "fingerprint_protect",
                                               "block_services", "block_incoming",
                                               "doh_enabled", "port_scan_detect",
                                               "process_monitor")
                     if getattr(p, k, False)]
            item = QListWidgetItem(f"{p.name}   ·   {', '.join(flags) or '—'}")
            item.setData(Qt.ItemDataRole.UserRole, p.name)
            self._profiles_list.addItem(item)
        self._sync_profile_buttons()

    def _sync_profile_buttons(self) -> None:
        has = bool(self._profiles_list.selectedItems())
        self._btn_edit_profile.setEnabled(has)
        self._btn_del_profile.setEnabled(has)

    def _selected_profile(self):
        items = self._profiles_list.selectedItems()
        if not items:
            return None
        name = items[0].data(Qt.ItemDataRole.UserRole)
        return next((p for p in self._cfg.custom_profiles if p.name == name), None)

    def _new_profile(self) -> None:
        from maze.gui.widgets.profile_dialog import ProfileDialog
        dlg = ProfileDialog(self._state, self,
                            taken={p.name for p in self._cfg.custom_profiles})
        if dlg.exec() and dlg.result_profile:
            self._cfg.custom_profiles.append(dlg.result_profile)
            self._profiles_changed()

    def _edit_profile(self) -> None:
        from maze.gui.widgets.profile_dialog import ProfileDialog
        current = self._selected_profile()
        if current is None:
            return
        dlg = ProfileDialog(self._state, self, existing=current,
                            taken={p.name for p in self._cfg.custom_profiles} - {current.name})
        if dlg.exec() and dlg.result_profile:
            idx = self._cfg.custom_profiles.index(current)
            self._cfg.custom_profiles[idx] = dlg.result_profile
            if self._cfg.profile == f"custom:{current.name}":
                self._cfg.profile = f"custom:{dlg.result_profile.name}"
            self._profiles_changed()

    def _delete_profile(self) -> None:
        current = self._selected_profile()
        if current is None:
            return
        s = self._state
        if QMessageBox.question(self, s.t("set_profile_delete"),
                                s.t("set_profile_delete_confirm").format(name=current.name)
                                ) != QMessageBox.StandardButton.Yes:
            return
        self._cfg.custom_profiles.remove(current)
        if self._cfg.profile == f"custom:{current.name}":
            self._cfg.profile = "home"
        self._profiles_changed()

    def _profiles_changed(self) -> None:
        self._save()
        self._populate_profiles()
        self._on_profiles_change()

    # ── automatic profile switching ───────────────────────────────────────

    def _build_auto_profile(self) -> QGroupBox:
        self._grp_auto = grp = QGroupBox()
        lay = QVBoxLayout(grp)
        lay.setSpacing(10)
        self._auto_cb = QCheckBox()
        self._auto_cb.setChecked(bool(self._cfg.auto_profile_switch))
        self._auto_cb.toggled.connect(self._on_auto_toggle)
        lay.addWidget(self._auto_cb)
        self._auto_hint = self._hint()
        lay.addWidget(self._auto_hint)
        self._trusted = _EditableList(self._add_trusted_text, self._remove_trusted,
                                      height=96)
        self._trusted.input.setVisible(False)
        self._trusted.add_btn.clicked.disconnect()
        self._trusted.add_btn.clicked.connect(self._trust_current_network)
        lay.addWidget(self._trusted)
        self._trust_status = self._hint()
        lay.addWidget(self._trust_status)
        return grp

    def _on_auto_toggle(self, enabled: bool) -> None:
        self._cfg.auto_profile_switch = enabled
        self._save()
        self._on_auto_profile_change()

    def _add_trusted_text(self, _text: str) -> bool:
        return False

    def _trust_current_network(self) -> None:
        # The engine's identity is what the watcher matches against; asking
        # the system again here could read a different interface and store an
        # id the watcher never sees.
        net_id = self._engine.identity.network_id
        if not net_id:
            from maze.utils.network_info import current_network_id
            net_id = current_network_id(self._engine.identity.interface
                                        or self._cfg.interface)
        if not net_id:
            self._trust_status.setText(self._state.t("set_no_network"))
            return
        if net_id not in self._cfg.trusted_networks:
            self._cfg.trusted_networks.append(net_id)
            self._save()
            self._on_auto_profile_change()
            self._trusted.set_items(self._cfg.trusted_networks)
        self._trust_status.setText(self._state.t("set_trusted_ok").format(net=net_id))

    def _remove_trusted(self, net_id: str) -> None:
        if net_id in self._cfg.trusted_networks:
            self._cfg.trusted_networks.remove(net_id)
            self._save()
            self._on_auto_profile_change()
        self._trusted.set_items(self._cfg.trusted_networks)

    # ── whitelist ─────────────────────────────────────────────────────────

    def _build_whitelist(self) -> QGroupBox:
        self._grp_wl = grp = QGroupBox()
        lay = QVBoxLayout(grp)
        lay.setSpacing(10)
        self._wl_hint = self._hint()
        lay.addWidget(self._wl_hint)
        self._wl = _EditableList(self._add_whitelist, self._remove_whitelist, height=110)
        self._wl.set_items(self._cfg.whitelist_ips)
        lay.addWidget(self._wl)
        return grp

    def _add_whitelist(self, ip: str) -> bool:
        if not _valid_address(ip):
            self._wl.input.setStyleSheet("border-color: #ff4d2e;")
            return False
        self._wl.input.setStyleSheet("")
        if ip not in self._cfg.whitelist_ips:
            self._cfg.whitelist_ips.append(ip)
            self._engine.set_whitelist(self._cfg.whitelist_ips)
            self._save()
            self._wl.set_items(self._cfg.whitelist_ips)
        return True

    def _remove_whitelist(self, ip: str) -> None:
        if ip in self._cfg.whitelist_ips:
            self._cfg.whitelist_ips.remove(ip)
            self._engine.set_whitelist(self._cfg.whitelist_ips)
            self._save()
        self._wl.set_items(self._cfg.whitelist_ips)

    # ── known processes ───────────────────────────────────────────────────

    def _build_processes(self) -> QGroupBox:
        self._grp_proc = grp = QGroupBox()
        lay = QVBoxLayout(grp)
        lay.setSpacing(10)
        self._proc_hint = self._hint()
        lay.addWidget(self._proc_hint)
        self._proc = _EditableList(self._add_process, self._remove_process,
                                   filterable=True, height=200)
        self._proc.set_items(sorted(self._cfg.known_processes, key=str.lower))
        lay.addWidget(self._proc)
        return grp

    def _add_process(self, name: str) -> bool:
        if name in self._cfg.known_processes:
            return True
        self._cfg.known_processes.append(name)
        pm = self._engine._modules.get("process")
        if pm:
            pm._known.add(name)
        self._save()
        self._proc.set_items(sorted(self._cfg.known_processes, key=str.lower))
        return True

    def _remove_process(self, name: str) -> None:
        if name in self._cfg.known_processes:
            self._cfg.known_processes.remove(name)
        pm = self._engine._modules.get("process")
        if pm:
            pm._known.discard(name)
        self._save()
        self._proc.set_items(sorted(self._cfg.known_processes, key=str.lower))

    # ── system ────────────────────────────────────────────────────────────

    def _build_system(self) -> QGroupBox:
        self._grp_system = grp = QGroupBox()
        lay = QVBoxLayout(grp)
        lay.setSpacing(10)
        self._autostart_cb = QCheckBox()
        self._autostart_cb.setChecked(autostart.is_enabled())
        self._autostart_cb.toggled.connect(self._toggle_autostart)
        lay.addWidget(self._autostart_cb)
        self._autostart_note = self._hint()
        lay.addWidget(self._autostart_note)
        self._about = self._hint()
        self._about.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self._about)
        return grp

    def _toggle_autostart(self, enabled: bool) -> None:
        if enabled:
            autostart.enable()
        else:
            autostart.disable()
        self._sync_autostart_note()

    def _sync_autostart_note(self) -> None:
        s = self._state
        # A system-wide entry can only be removed with root; say so rather
        # than leaving the app to keep launching on login with the box clear.
        if autostart.is_system_wide() and not self._autostart_cb.isChecked():
            self._autostart_note.setText(
                s.t("set_autostart_system").format(path=autostart.SYSTEM_PATH))
            self._autostart_note.setVisible(True)
        else:
            self._autostart_note.setVisible(False)

    def _about_text(self) -> str:
        s = self._state
        helper = getattr(self._engine, "helper", None)
        connected = bool(helper and helper.is_connected())
        return "\n".join([
            f"Maze Guard {maze.__version__}",
            f"{s.t('dash_iface')}: {self._engine.identity.interface or self._cfg.interface}",
            f"{s.t('dash_helper')}: "
            + (s.t("set_helper_outdated") if connected and getattr(helper, "outdated", False)
               else s.t("dash_helper_ok" if connected else "dash_helper_missing")),
            f"{s.t('set_config_file')}: {CONFIG_PATH}",
        ])

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._about.setText(self._about_text())

    # ── i18n ──────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._sync_appearance()
        self._grp_appearance.setTitle(s.t("set_appearance"))
        self._lbl_lang.setText(s.t("set_language"))
        self._lbl_theme.setText(s.t("set_theme"))
        self._theme.setItemText(0, s.t("theme_dark"))
        self._theme.setItemText(1, s.t("theme_light"))

        self._grp_response.setTitle(s.t("set_response"))
        self._lbl_notify.setText(s.t("set_notify"))
        for i, value in enumerate(self._NOTIFY_CHOICES):
            self._notify_combo.setItemText(i, s.t(f"set_notify_{value}"))
        self._lbl_threshold.setText(s.t("set_threshold"))
        self._threshold_spin.setToolTip(s.t("set_threshold_tip"))
        self._newdev_cb.setText(s.t("set_notify_new_devices"))
        self._auto_block_cb.setText(s.t("set_auto_block"))
        self._auto_block_cb.setToolTip(s.t("set_auto_block_tip"))
        self._mac_block_cb.setText(s.t("set_block_by_mac"))
        self._mac_block_cb.setToolTip(s.t("set_block_by_mac_tip"))

        self._grp_profiles.setTitle(s.t("set_profiles"))
        self._profiles_hint.setText(s.t("set_profiles_hint"))
        self._btn_new_profile.setText(s.t("set_profile_new"))
        self._btn_edit_profile.setText(s.t("set_profile_edit"))
        self._btn_del_profile.setText(s.t("set_profile_delete"))
        self._populate_profiles()

        self._grp_auto.setTitle(s.t("set_auto_profile"))
        self._auto_cb.setText(s.t("set_auto_profile_cb"))
        self._auto_hint.setText(s.t("set_auto_profile_hint"))
        self._trusted.add_btn.setText(s.t("set_trust_current"))
        self._trusted.remove_btn.setText(s.t("set_remove"))
        self._trusted.set_items(self._cfg.trusted_networks)

        self._grp_wl.setTitle(s.t("set_whitelist"))
        self._wl_hint.setText(s.t("set_whitelist_hint"))
        self._wl.input.setPlaceholderText(s.t("set_whitelist_placeholder"))
        self._wl.add_btn.setText(s.t("set_add"))
        self._wl.remove_btn.setText(s.t("set_remove"))

        self._grp_proc.setTitle(s.t("set_processes"))
        self._proc_hint.setText(s.t("set_processes_hint"))
        self._proc.filter.setPlaceholderText(s.t("set_filter"))
        self._proc.input.setPlaceholderText(s.t("set_process_placeholder"))
        self._proc.add_btn.setText(s.t("set_add"))
        self._proc.remove_btn.setText(s.t("set_remove"))

        self._grp_system.setTitle(s.t("set_system"))
        self._autostart_cb.setText(s.t("set_autostart"))
        self._sync_autostart_note()
        self._about.setText(self._about_text())
