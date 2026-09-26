import asyncio
import time
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTabWidget, QFrame, QApplication,
    QDialog, QDialogButtonBox, QTableWidgetItem,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
from maze.core.engine import MazeEngine
from maze.core.events import Event, EventType, ThreatLevel, escalate
from maze.core.profile import Profile
from maze.gui.app_state import AppState
from maze.gui.icons import create_app_icon
from maze.gui.theme import get_stylesheet
from maze.gui.tray import SystemTray
from maze.gui.widgets.threat_level import ThreatLevelWidget
from maze.gui.widgets.event_list import EventListWidget
from maze.gui.widgets.connection_map import ConnectionMapWidget
from maze.gui.widgets.device_list import DeviceListWidget
from maze.gui.widgets.module_status import ModuleStatusWidget
from maze.gui.widgets.dashboard_view import DashboardView
from maze.gui.widgets.firewall_view import FirewallView
from maze.utils.config import MazeConfig, save_config


# Profiles that mean "this network is not mine" — the user has already told
# us that strangers are expected here.
_UNTRUSTED_PROFILES = {Profile.PUBLIC, Profile.PARANOID, Profile.SECURE}

_PROFILES = [
    (Profile.HOME,     "profile_home"),
    (Profile.PUBLIC,   "profile_public"),
    (Profile.PARANOID, "profile_paranoid"),
    (Profile.SECURE,   "profile_secure"),
    (Profile.MANUAL,   "profile_manual"),
]


class _TitleBar(QWidget):
    """Draggable custom title bar. Uses startSystemMove() for Wayland compatibility."""

    def __init__(self, window: QMainWindow, parent=None):
        super().__init__(parent)
        self._window = window

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self._window.windowHandle()
            if handle:
                handle.startSystemMove()
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            if self._window.isMaximized():
                self._window.showNormal()
            else:
                self._window.showMaximized()
        super().mouseDoubleClickEvent(event)


class Dashboard(QMainWindow):
    def __init__(self, engine: MazeEngine, cfg: MazeConfig, state: AppState):
        super().__init__()
        self.engine = engine
        self.cfg = cfg
        self.state = state
        self._threat_level = ThreatLevel.SAFE
        # New-device popup damping, per network — see _new_device_popup_allowed.
        self._newdev_net = ""
        self._newdev_times: list[float] = []
        self._newdev_muted_until = 0.0
        # Threat popup damping — see _popup_allowed.
        self._popup_last: dict[tuple, float] = {}
        self._popup_times: list[float] = []

        self.setWindowTitle("Maze Guard")
        self.setWindowIcon(create_app_icon(64))
        self.setMinimumSize(1100, 720)
        self.resize(1280, 820)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        self._build_ui()
        self._setup_tray()
        self._setup_timer()
        self._connect_bus()
        self._setup_auto_profile()

        state.language_changed.connect(self.retranslate)
        state.theme_changed.connect(self._on_theme_changed)

    # ── UI ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._make_header())
        root.addWidget(self._make_separator())
        root.addWidget(self._make_tabs())

    def _make_header(self) -> _TitleBar:
        header = _TitleBar(self)
        header.setObjectName("header")
        header.setFixedHeight(50)

        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 0, 0, 0)
        layout.setSpacing(12)

        logo = QLabel("MAZE GUARD")
        logo.setObjectName("logo")
        layout.addWidget(logo)

        layout.addStretch()

        self.threat_widget = ThreatLevelWidget(self.state)
        layout.addWidget(self.threat_widget)

        # Reset threat level button
        reset_btn = QPushButton("↺")
        reset_btn.setObjectName("win_btn")
        reset_btn.setToolTip("Reset threat level")
        reset_btn.setFixedWidth(32)
        reset_btn.clicked.connect(self._reset_threat)
        layout.addWidget(reset_btn)

        layout.addStretch()

        self.profile_label = QLabel()
        self.profile_label.setStyleSheet("font-size: 12px;")
        layout.addWidget(self.profile_label)

        self.profile_combo = QComboBox()
        self.profile_combo.blockSignals(True)
        for _, i18n_key in _PROFILES:
            self.profile_combo.addItem(self.state.t(i18n_key))
        # Reflect the persisted startup profile (applied by app.run) so the
        # combo matches what the engine is actually running.
        for i, (p, _) in enumerate(_PROFILES):
            if p.value == getattr(self.cfg, "profile", "home"):
                self.profile_combo.setCurrentIndex(i)
                break
        self.profile_combo.blockSignals(False)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_change)
        layout.addWidget(self.profile_combo)

        # "+" button to create custom profile
        add_profile_btn = QPushButton("+")
        add_profile_btn.setFixedWidth(28)
        add_profile_btn.setFixedHeight(28)
        add_profile_btn.setToolTip("Create custom profile")
        add_profile_btn.clicked.connect(self._open_profile_dialog)
        layout.addWidget(add_profile_btn)

        self.lang_combo = QComboBox()
        self.lang_combo.addItem("English", "en")
        self.lang_combo.addItem("Türkçe", "tr")
        self.lang_combo.setFixedWidth(90)
        self.lang_combo.currentIndexChanged.connect(self._on_lang_change)
        layout.addWidget(self.lang_combo)

        self.theme_btn = QPushButton()
        self.theme_btn.setFixedWidth(62)
        self.theme_btn.clicked.connect(self.state.toggle_theme)
        layout.addWidget(self.theme_btn)

        # ── Window controls ──────────────────────────────────────────────
        layout.addSpacing(8)

        self._min_btn = QPushButton("─")
        self._min_btn.setObjectName("win_btn")
        self._min_btn.setToolTip("Minimize")
        self._min_btn.clicked.connect(self.showMinimized)
        layout.addWidget(self._min_btn)

        self._max_btn = QPushButton("□")
        self._max_btn.setObjectName("win_btn")
        self._max_btn.setToolTip("Maximize / Restore")
        self._max_btn.clicked.connect(self._toggle_maximize)
        layout.addWidget(self._max_btn)

        self._close_btn = QPushButton("✕")
        self._close_btn.setObjectName("win_close")
        self._close_btn.setToolTip("Minimize to tray")
        self._close_btn.clicked.connect(self.hide)
        layout.addWidget(self._close_btn)

        self._update_theme_btn()
        self._sync_lang_combo()
        self.profile_label.setText(self.state.t("profile_label") + ":")
        return header

    def _make_separator(self) -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        return sep

    def _make_tabs(self) -> QTabWidget:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.dash_view     = DashboardView(self.state, self.engine, self.cfg)
        self.event_list    = EventListWidget(self.state, self.engine)
        self.conn_map      = ConnectionMapWidget(self.state)
        self.device_list   = DeviceListWidget(self.state, self.engine, self.cfg)
        self.module_status = ModuleStatusWidget(self.state, self.engine)
        self.firewall_view = FirewallView(self.state, self.engine)

        from maze.gui.widgets.threats_view import ThreatsView
        self.threats_view = ThreatsView(self.state, self.engine)

        from maze.gui.widgets.settings_view import SettingsView
        self.settings_view = SettingsView(
            self.state, self.engine, self.cfg, self._save_config,
            on_auto_profile_change=self.refresh_auto_profile,
        )

        self.tabs.addTab(self.dash_view,     self.state.t("tab_dashboard"))
        self.tabs.addTab(self.threats_view,  self.state.t("tab_threats"))
        self.tabs.addTab(self.event_list,    self.state.t("tab_events"))
        self.tabs.addTab(self.conn_map,      self.state.t("tab_connections"))
        self.tabs.addTab(self.device_list,   self.state.t("tab_devices"))
        self.tabs.addTab(self.module_status, self.state.t("tab_protection"))
        self.tabs.addTab(self.firewall_view, self.state.t("tab_firewall"))
        self.tabs.addTab(self.settings_view, self.state.t("tab_settings"))

        # Load custom profiles into combo (Task 15)
        self._custom_profiles = list(self.cfg.custom_profiles)
        for p in self._custom_profiles:
            self.profile_combo.addItem(getattr(p, 'name', str(p)))

        return self.tabs

    # ── Close → tray ─────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        event.ignore()
        self.hide()

    # Polling while hidden in the tray is pure waste: the tabs each spawn
    # firewall-cmd / iw / ip and walk /proc through the helper on their
    # timers, which measured as ~40% of a core for a window nobody could
    # see. Every timer callback checks isVisible() instead — a hidden main
    # window makes all of them false — and showEvent brings the view back
    # up to date the moment it is restored. Threat detection is unaffected:
    # it runs in the engine and reaches the tray through the event bus.
    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh()

    # ── Tray ─────────────────────────────────────────────────────────────

    def _setup_tray(self) -> None:
        self._tray = SystemTray(on_show=self._restore,
                                on_quit=self._quit_with_summary,
                                on_notification_clicked=self._open_context)
        self._tray.show()

    def _open_context(self, context: str) -> None:
        """Open the tab that explains the notification just clicked."""
        tab = {"threats": self.threats_view, "devices": self.device_list,
               "events": self.event_list}.get(context)
        if tab is not None:
            self.tabs.setCurrentWidget(tab)

    def _restore(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # ── Auto profile switching ───────────────────────────────────────────

    def _setup_auto_profile(self) -> None:
        from maze.network.auto_profile import AutoProfileWatcher
        self._auto_watcher = AutoProfileWatcher(
            self.engine.identity,
            self.cfg.trusted_networks,
            self._on_auto_profile,
        )
        self.refresh_auto_profile()

    def refresh_auto_profile(self) -> None:
        """(Re)configure the auto-profile watcher from current config.
        Called at startup and whenever Settings changes the toggle or the
        trusted-networks list."""
        self._auto_watcher.set_trusted(self.cfg.trusted_networks)
        if self.cfg.auto_profile_switch:
            self._auto_watcher.start()
        else:
            self._auto_watcher.stop()

    def _on_auto_profile(self, profile: Profile) -> None:
        # Drive the combo so the UI stays in sync; it triggers _on_profile_change.
        for i, (p, _) in enumerate(_PROFILES):
            if p == profile:
                if self.profile_combo.currentIndex() != i:
                    self.profile_combo.setCurrentIndex(i)
                    # Say what just happened, once per actual switch — never
                    # on a re-evaluation that lands on the same profile, so a
                    # login on the usual network stays silent. The public
                    # message carries the one action worth knowing: how to
                    # make this network trusted if it is in fact yours.
                    net = self.engine.identity.network_id or ""
                    label = net.split(":", 1)[1] if ":" in net else net
                    if profile == Profile.PUBLIC:
                        self._tray.notify_warning(
                            self.state.t("notif_profile_public_title"),
                            self.state.t("notif_profile_public_body").format(net=label),
                            context="events")
                    elif profile == Profile.HOME:
                        self._tray.notify_warning(
                            self.state.t("notif_profile_home_title"),
                            self.state.t("notif_profile_home_body").format(net=label),
                            context="events")
                break

    # ── Refresh timer ────────────────────────────────────────────────────

    def _setup_timer(self) -> None:
        self._timer = QTimer(self)
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        # Switching tabs should not wait for the next tick.
        self.tabs.currentChanged.connect(lambda _i: self._refresh())

    def _refresh(self) -> None:
        if not self.isVisible():
            return
        # Only the tab on screen is worth a round trip: the connection map
        # walks /proc through the helper and the protection tab re-reads the
        # firewall, and a hidden tab redraws nothing anyone can see.
        monitor = self.engine.process_monitor
        if monitor and self.conn_map.isVisible():
            asyncio.ensure_future(self._refresh_connections(monitor))

        watcher = self.engine.arp_watcher
        if watcher and self.device_list.isVisible():
            self.device_list.update_devices(watcher.devices)

        if self.module_status.isVisible():
            self.module_status.refresh()

    async def _refresh_connections(self, monitor) -> None:
        conns = await monitor.snapshot()
        self.conn_map.update_connections(conns)

    # ── Event bus ────────────────────────────────────────────────────────

    def _connect_bus(self) -> None:
        self.engine.bus.subscribe_all(self._on_event)

    async def _on_event(self, event: Event) -> None:
        if event.type == EventType.DEVICE_FOUND:
            watcher = self.engine.arp_watcher
            if watcher:
                self.device_list.update_devices(watcher.devices)
            return

        if event.type == EventType.DEVICE_NEW:
            # Worth interrupting someone for, but not an attack: it must not
            # colour the threat header, which is reserved for things aimed at
            # this host.
            self.event_list.add_event(event)
            self.dash_view.increment_event_count()
            watcher = self.engine.arp_watcher
            if watcher:
                self.device_list.update_devices(watcher.devices)
            if self._new_device_popup_allowed(event):
                self._tray.notify_warning(
                    self.state.t("notif_new_device"), event.message,
                    context="devices")
            return

        self.event_list.add_event(event)
        self.dash_view.increment_event_count()

        if event.level == ThreatLevel.DANGEROUS:
            self._raise_threat_level(ThreatLevel.DANGEROUS)
            if self._may_notify(ThreatLevel.DANGEROUS) and \
                    self._popup_allowed(event):
                self._tray.notify_danger(
                    self.state.t("notif_danger_title"),
                    event.message, context="threats",
                )
        elif event.level == ThreatLevel.SUSPICIOUS:
            self._raise_threat_level(ThreatLevel.SUSPICIOUS)
            if self._may_notify(ThreatLevel.SUSPICIOUS) and \
                    self._popup_allowed(event):
                self._tray.notify_warning(
                    self.state.t("notif_warn_title"),
                    event.message, context="events",
                )

    # A "new device" popup is the signal a HOME user wants: someone joined my
    # network. On a public network it is the opposite of a signal — strangers'
    # phones (most with randomised MACs) come and go all day, and every one of
    # them is "new". A café session used to produce a popup per arrival. Two
    # guards, both leaving the event list and Devices tab fully populated:
    #   * the untrusted-network profiles (PUBLIC, PARANOID, SECURE) never pop
    #     for new devices — those profiles exist precisely because the network
    #     is full of strangers;
    #   * on any other profile a burst is damped per network: after
    #     _NEWDEV_BURST popups within _NEWDEV_WINDOW, one last popup says the
    #     rest are being logged silently, then nothing for _NEWDEV_MUTE. A
    #     home network with three family phones never hits it; a hotspot with
    #     a manually chosen Home profile does, once.
    _NEWDEV_WINDOW = 600.0
    _NEWDEV_BURST = 2
    _NEWDEV_MUTE = 3600.0

    def _new_device_popup_allowed(self, event: Event) -> bool:
        if not getattr(self.cfg, "notify_new_devices", True):
            return False
        if self.engine.profiles.current in _UNTRUSTED_PROFILES:
            return False
        net = (event.data or {}).get("network_id", "")
        now = time.monotonic()
        if net != self._newdev_net:
            self._newdev_net = net
            self._newdev_times = []
            self._newdev_muted_until = 0.0
        if now < self._newdev_muted_until:
            return False
        self._newdev_times = [t for t in self._newdev_times
                              if now - t < self._NEWDEV_WINDOW]
        self._newdev_times.append(now)
        if len(self._newdev_times) > self._NEWDEV_BURST:
            self._newdev_muted_until = now + self._NEWDEV_MUTE
            self._tray.notify_warning(
                self.state.t("notif_new_device"),
                self.state.t("notif_new_devices_muted"), context="devices")
            return False
        return True

    # The same finding about the same source pops up once per _POPUP_REPEAT,
    # and no more than _POPUP_BURST popups of any kind in _POPUP_WINDOW. A
    # detector that misfires — or an attacker who trips one deliberately —
    # must not bury the desktop in identical notifications; every event still
    # lands in the event list.
    _POPUP_REPEAT = 600.0
    _POPUP_WINDOW = 60.0
    _POPUP_BURST = 3

    def _popup_allowed(self, event: Event) -> bool:
        data = event.data or {}
        source = (data.get("src") or data.get("ip") or data.get("hostname")
                  or data.get("domain") or data.get("bssid")
                  or data.get("process") or "")
        key = (event.type, str(source))
        now = time.monotonic()
        if now - self._popup_last.get(key, -self._POPUP_REPEAT) < self._POPUP_REPEAT:
            return False
        self._popup_times = [t for t in self._popup_times
                             if now - t < self._POPUP_WINDOW]
        if len(self._popup_times) >= self._POPUP_BURST:
            return False
        self._popup_last[key] = now
        self._popup_times.append(now)
        if len(self._popup_last) > 512:
            for old in sorted(self._popup_last,
                              key=self._popup_last.get)[:256]:
                del self._popup_last[old]
        return True

    def _raise_threat_level(self, level: ThreatLevel) -> None:
        """Show the worst level seen since the last reset, not the newest."""
        raised = escalate(self._threat_level, level)
        if raised is self._threat_level:
            return
        self._threat_level = raised
        self.threat_widget.update_level(raised)
        self.dash_view.update_threat_level(raised)

    def _may_notify(self, level: ThreatLevel) -> bool:
        """Whether ``level`` is allowed to raise a desktop popup.

        The dashboard event list always gets the event; this gates only the
        tray notification, per cfg.notify_min_level ("dangerous" | "suspicious"
        | "off"). Unknown values fall back to the default rather than silently
        muting alerts.
        """
        setting = str(getattr(self.cfg, "notify_min_level", "dangerous")).lower()
        if setting == "off":
            return False
        if setting == "suspicious":
            return True
        return level == ThreatLevel.DANGEROUS

    # ── Controls ─────────────────────────────────────────────────────────

    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _reset_threat(self) -> None:
        self._threat_level = ThreatLevel.SAFE
        self.threat_widget.update_level(ThreatLevel.SAFE)
        self.dash_view.reset_threat_level()

    def _on_profile_change(self, index: int) -> None:
        if index < len(_PROFILES):
            profile = _PROFILES[index][0]
            self.engine.profiles.set(profile)
            # Persist so the choice is restored on next launch.
            self.cfg.profile = profile.value
            save_config(self.cfg)
        else:
            custom_idx = index - len(_PROFILES)
            custom_profiles = getattr(self, '_custom_profiles', self.cfg.custom_profiles)
            if custom_idx < len(custom_profiles):
                p = custom_profiles[custom_idx]
                asyncio.ensure_future(self._apply_custom_profile(p))

    async def _apply_custom_profile(self, p) -> None:
        await self.engine.apply_custom_profile(p)

    def _open_profile_dialog(self) -> None:
        from maze.gui.widgets.profile_dialog import ProfileDialog
        dlg = ProfileDialog(self)
        if dlg.exec() and dlg.result_profile:
            p = dlg.result_profile
            self.cfg.custom_profiles.append(p)
            save_config(self.cfg)
            self.profile_combo.addItem(p.name)
            if not hasattr(self, '_custom_profiles'):
                self._custom_profiles = []
            self._custom_profiles.append(p)

    def _save_config(self) -> None:
        save_config(self.cfg)

    def _quit_with_summary(self) -> None:
        # Route through an async step so the incoming-block shield can be torn
        # down before the process exits.
        asyncio.ensure_future(self._async_quit())

    async def _async_quit(self) -> None:
        # The inbound shield used to be torn down here, on the grounds that its
        # --permanent zone target outlives the process. That traded a security
        # property for tidiness: quitting the app silently opened the machine
        # up, and now that lowering the shield requires authorisation it would
        # also put a password prompt in the way of closing a window. The shield
        # stays; the summary says so, with the way to undo it.
        self._shield_left_up = False
        try:
            fw = self.engine._fw()
            self._shield_left_up = bool(fw and (await fw.sync_state()).incoming_blocked)
        except Exception:
            pass
        # Flush attacker dossiers so nothing learned this session is lost.
        try:
            self.engine.incidents.save()
        except Exception:
            pass
        self._show_summary_and_quit()

    def _show_summary_and_quit(self) -> None:
        tbl = self.event_list._table
        total = tbl.rowCount()
        dangerous  = 0
        suspicious = 0
        for i in range(total):
            level_item = tbl.item(i, 1)
            if not level_item:
                continue
            txt = level_item.text().lower()
            if "danger" in txt:
                dangerous += 1
            elif "suspic" in txt:
                suspicious += 1

        shield_up = getattr(self, "_shield_left_up", False)
        if total == 0 and not shield_up:
            QApplication.instance().quit()
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Session Summary")
        dlg.setFixedWidth(320)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        title = QLabel("Session Summary")
        title.setStyleSheet("font-size: 15px; font-weight: bold;")
        layout.addWidget(title)

        for label, value, color in [
            ("Total events",  str(total),      ""),
            ("Dangerous",     str(dangerous),  "#e05c5c" if dangerous  else ""),
            ("Suspicious",    str(suspicious), "#e0a050" if suspicious else ""),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(label + ":")
            lbl.setStyleSheet("color: #888; font-size: 12px;")
            val = QLabel(value)
            if color:
                val.setStyleSheet(f"font-weight: bold; color: {color};")
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)
            layout.addLayout(row)

        if shield_up:
            # Never let a protection outlive the app without saying so — an
            # unexplained DROP zone is a support ticket waiting to happen.
            note = QLabel(self.state.t("quit_shield_note"))
            note.setWordWrap(True)
            note.setStyleSheet("color: #888; font-size: 11px; padding-top: 6px;")
            layout.addWidget(note)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btns.accepted.connect(dlg.accept)
        layout.addWidget(btns)

        dlg.exec()
        QApplication.instance().quit()

    def _on_lang_change(self, index: int) -> None:
        lang = self.lang_combo.itemData(index)
        self.state.set_language(lang)

    def _sync_lang_combo(self) -> None:
        self.lang_combo.blockSignals(True)
        for i in range(self.lang_combo.count()):
            if self.lang_combo.itemData(i) == self.state.language:
                self.lang_combo.setCurrentIndex(i)
                break
        self.lang_combo.blockSignals(False)

    def _on_theme_changed(self, theme: str) -> None:
        app = QApplication.instance()
        if app:
            app.setStyleSheet(get_stylesheet(theme))
        self._update_theme_btn()

    def _update_theme_btn(self) -> None:
        self.theme_btn.setText(
            self.state.t("theme_light") if self.state.theme == "dark"
            else self.state.t("theme_dark")
        )

    # ── i18n ─────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        self.profile_label.setText(self.state.t("profile_label") + ":")
        self._update_theme_btn()
        self._sync_lang_combo()

        self.profile_combo.blockSignals(True)
        for i, (_, i18n_key) in enumerate(_PROFILES):
            self.profile_combo.setItemText(i, self.state.t(i18n_key))
        self.profile_combo.blockSignals(False)

        for index, key in enumerate((
            "tab_dashboard", "tab_threats", "tab_events", "tab_connections",
            "tab_devices", "tab_protection", "tab_firewall", "tab_settings",
        )):
            self.tabs.setTabText(index, self.state.t(key))
