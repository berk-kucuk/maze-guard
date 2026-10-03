import asyncio
import time
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QStackedWidget, QFrame, QApplication,
    QDialog, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QKeySequence, QShortcut
from maze.core.engine import MazeEngine
from maze.core.events import Event, EventType, ThreatLevel, escalate
from maze.core.profile import Profile
from maze.gui.app_state import AppState
from maze.gui.icons import create_app_icon
from maze.gui.theme import THREAT_COLORS, get_stylesheet
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

# Events that record what Maze Guard or the user did, or a follow-up to an
# alert already shown — never a new threat. They go to the event list only:
# they neither pop up nor raise the threat level. Stopping the firewall
# yourself used to turn the header orange and say "Something is worth a
# look", and every reconnaissance result arrived as a second popup.
_QUIET_TYPES = {
    EventType.RECON_RESULT, EventType.FIREWALL_CHANGED, EventType.MODULE_TOGGLED,
    EventType.PROFILE_CHANGED, EventType.ENGINE_READY, EventType.IP_MOVED,
}
# Active attacks the engine answers with an automatic block. Their popup
# waits briefly for that block so one attack is one notification ("attack
# blocked") instead of two in a row.
_BLOCKABLE = {EventType.PORT_SCAN, EventType.STEALTH_SCAN, EventType.ATTACK_CHAIN}
_COALESCE_MS = 2500

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


# (attribute, title key, subtitle key). Order is the sidebar order.
_PAGES = [
    ("dash_view",     "tab_dashboard",   "sub_dashboard"),
    ("threats_view",  "tab_threats",     "sub_threats"),
    ("event_list",    "tab_events",      "sub_events"),
    ("device_list",   "tab_devices",     "sub_devices"),
    ("conn_map",      "tab_connections", "sub_connections"),
    ("module_status", "tab_protection",  "sub_protection"),
    ("firewall_view", "tab_firewall",    "sub_firewall"),
    ("settings_view", "tab_settings",    "sub_settings"),
]


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
        self._popup_times: dict[ThreatLevel, list[float]] = {}
        # Attack popups waiting for their automatic block, by source.
        self._pending_popups: dict[str, Event] = {}

        self.setWindowTitle("Maze Guard")
        self.setWindowIcon(create_app_icon(64))
        self.setMinimumSize(1100, 700)
        self.resize(1320, 840)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        self._build_ui()
        self._setup_tray()
        self._setup_timer()
        self._connect_bus()
        self._setup_auto_profile()
        self._setup_shortcuts()
        self.event_list.open_source = self._open_source

        state.language_changed.connect(self.retranslate)
        state.theme_changed.connect(self._on_theme_changed)
        self.retranslate()

    # ── UI ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("content")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.tabs = QStackedWidget()
        self.tabs.setObjectName("pages")
        self._build_pages()

        root.addWidget(self._make_sidebar())
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self._make_topbar())
        right.addWidget(self.tabs, 1)
        root.addLayout(right, 1)

        self.tabs.currentChanged.connect(self._on_page_changed)
        self._go(0)

    def _build_pages(self) -> None:
        from maze.gui.widgets.threats_view import ThreatsView
        from maze.gui.widgets.settings_view import SettingsView

        self.dash_view     = DashboardView(self.state, self.engine, self.cfg,
                                           navigate=self._open_context)
        self.threats_view  = ThreatsView(self.state, self.engine)
        self.event_list    = EventListWidget(self.state, self.engine)
        self.device_list   = DeviceListWidget(self.state, self.engine, self.cfg)
        self.conn_map      = ConnectionMapWidget(self.state, self.engine)
        self.module_status = ModuleStatusWidget(self.state, self.engine)
        self.firewall_view = FirewallView(self.state, self.engine)
        self.settings_view = SettingsView(
            self.state, self.engine, self.cfg, self._save_config,
            on_auto_profile_change=self.refresh_auto_profile,
            on_profiles_change=self.reload_custom_profiles,
        )
        for attr, _t, _s in _PAGES:
            self.tabs.addWidget(getattr(self, attr))

    def _make_sidebar(self) -> QFrame:
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(224)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(14, 16, 14, 14)
        lay.setSpacing(4)

        brand = QHBoxLayout()
        brand.setSpacing(10)
        icon = QLabel()
        icon.setPixmap(create_app_icon(64).pixmap(30, 30))
        brand.addWidget(icon)
        names = QVBoxLayout()
        names.setSpacing(0)
        logo = QLabel("MAZE GUARD")
        logo.setObjectName("logo")
        self._logo_sub = QLabel()
        self._logo_sub.setObjectName("logo_sub")
        names.addWidget(logo)
        names.addWidget(self._logo_sub)
        brand.addLayout(names)
        brand.addStretch()
        lay.addLayout(brand)
        lay.addSpacing(18)

        self._nav: list[QPushButton] = []
        self._threat_badge = QLabel()
        self._threat_badge.setObjectName("nav_badge")
        self._threat_badge.setFixedHeight(18)
        self._threat_badge.setMinimumWidth(20)
        self._threat_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._threat_badge.setVisible(False)
        for i, (attr, _t, _s) in enumerate(_PAGES):
            btn = QPushButton()
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, i=i: self._go(i))
            if attr == "threats_view":
                # The count of tracked attackers rides on the nav item, so a
                # new one is visible from any page.
                inner = QHBoxLayout(btn)
                inner.setContentsMargins(0, 0, 10, 0)
                inner.addStretch()
                inner.addWidget(self._threat_badge, 0, Qt.AlignmentFlag.AlignVCenter)
            self._nav.append(btn)
            lay.addWidget(btn)
            if attr == "conn_map":
                lay.addSpacing(10)

        lay.addStretch()

        # Status block: current threat level and the active profile.
        status = QFrame()
        status.setObjectName("card")
        sl = QVBoxLayout(status)
        sl.setContentsMargins(12, 10, 12, 12)
        sl.setSpacing(8)
        top = QHBoxLayout()
        self.threat_widget = ThreatLevelWidget(self.state)
        top.addWidget(self.threat_widget)
        top.addStretch()
        self._reset_btn = QPushButton("↺")
        self._reset_btn.setObjectName("link")
        self._reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_btn.clicked.connect(self._reset_threat)
        top.addWidget(self._reset_btn)
        sl.addLayout(top)

        self.profile_label = QLabel()
        self.profile_label.setObjectName("card_title")
        sl.addWidget(self.profile_label)
        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(0)
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
        self._custom_profiles: list = []
        self.reload_custom_profiles()
        self.profile_combo.currentIndexChanged.connect(self._on_profile_change)
        sl.addWidget(self.profile_combo)
        lay.addWidget(status)
        return side

    def _make_topbar(self) -> _TitleBar:
        bar = _TitleBar(self)
        bar.setObjectName("topbar")
        bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        bar.setFixedHeight(64)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(24, 0, 0, 0)
        lay.setSpacing(0)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        titles.addStretch()
        self._page_title = QLabel()
        self._page_title.setObjectName("page_title")
        self._page_subtitle = QLabel()
        self._page_subtitle.setObjectName("page_subtitle")
        titles.addWidget(self._page_title)
        titles.addWidget(self._page_subtitle)
        titles.addStretch()
        lay.addLayout(titles)
        lay.addStretch()

        controls = QVBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        btns = QHBoxLayout()
        btns.setSpacing(0)
        self._min_btn = QPushButton("─")
        self._min_btn.setObjectName("win_btn")
        self._min_btn.clicked.connect(self.showMinimized)
        self._max_btn = QPushButton("□")
        self._max_btn.setObjectName("win_btn")
        self._max_btn.clicked.connect(self._toggle_maximize)
        self._close_btn = QPushButton("✕")
        self._close_btn.setObjectName("win_close")
        self._close_btn.clicked.connect(self.hide)
        for b in (self._min_btn, self._max_btn, self._close_btn):
            btns.addWidget(b)
        controls.addLayout(btns)
        controls.addStretch()
        lay.addLayout(controls)
        return bar

    def _setup_shortcuts(self) -> None:
        # Ctrl+1 … Ctrl+8 jump to a page; Ctrl+F searches the page on screen.
        for i in range(len(_PAGES)):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self,
                      activated=lambda i=i: self._go(i))
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_search)

    def _focus_search(self) -> None:
        search = getattr(self.tabs.currentWidget(), "_search", None)
        if search is not None:
            search.setFocus()
            search.selectAll()

    def _open_source(self, ip: str) -> None:
        """Show the Threats dossier for ``ip`` when there is one."""
        if self.threats_view.select(ip):
            self._go(self.tabs.indexOf(self.threats_view))

    def _sync_tray(self) -> None:
        if not hasattr(self, "_tray"):
            return
        s = self.state
        combo = self.profile_combo
        self._tray.build_menu(
            {"open": s.t("tray_open"), "profile": s.t("tray_profile"),
             "quit": s.t("tray_quit")},
            [combo.itemText(i) for i in range(combo.count())],
            combo.currentIndex(), combo.setCurrentIndex)
        self._tray.set_tooltip(s.t("tray_tooltip").format(
            level=s.t(f"threat_{self._threat_level.value}")))

    def _go(self, index: int) -> None:
        self.tabs.setCurrentIndex(index)
        self._on_page_changed(index)

    def _on_page_changed(self, index: int) -> None:
        for i, btn in enumerate(self._nav):
            btn.setChecked(i == index)
        _attr, title_key, sub_key = _PAGES[index]
        self._page_title.setText(self.state.t(title_key))
        self._page_subtitle.setText(self.state.t(sub_key))
        self._refresh()

    def reload_custom_profiles(self) -> None:
        """(Re)list the custom profiles after the built-in ones. Called when
        Settings adds or removes one."""
        combo = self.profile_combo
        current = getattr(self.cfg, "profile", "")
        combo.blockSignals(True)
        while combo.count() > len(_PROFILES):
            combo.removeItem(combo.count() - 1)
        self._custom_profiles = list(self.cfg.custom_profiles)
        for i, p in enumerate(self._custom_profiles):
            name = getattr(p, "name", str(p))
            combo.addItem(name)
            # A persisted custom choice can only be selected once its entry
            # exists — the built-in pass above runs before this.
            if current == f"custom:{name}":
                combo.setCurrentIndex(len(_PROFILES) + i)
        combo.blockSignals(False)
        self._sync_tray()

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
        """Open the page that explains the notification (or tile) clicked."""
        page = {"overview": self.dash_view, "threats": self.threats_view,
                "events": self.event_list, "devices": self.device_list,
                "connections": self.conn_map, "protection": self.module_status,
                "firewall": self.firewall_view,
                "settings": self.settings_view}.get(context)
        if page is not None:
            self._go(self.tabs.indexOf(page))

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
                    if not self._notifications_on():
                        pass
                    elif profile == Profile.PUBLIC:
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

        self._update_threat_badge()

    def _update_threat_badge(self) -> None:
        count = len(self.engine.incidents.active(60))
        self._threat_badge.setText(str(count))
        self._threat_badge.setVisible(count > 0)

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
            self.dash_view.add_event(event)
            watcher = self.engine.arp_watcher
            if watcher:
                self.device_list.update_devices(watcher.devices)
            if self._notifications_on() and self._new_device_popup_allowed(event):
                self._tray.notify_warning(
                    self.state.t("notif_new_device"), event.message,
                    context="devices")
            return

        self.event_list.add_event(event)
        self.dash_view.add_event(event)
        self._update_threat_badge()
        if event.type in _QUIET_TYPES or event.level == ThreatLevel.SAFE:
            return

        self._raise_threat_level(event.level)
        if event.type == EventType.IP_BLOCKED:
            self._on_auto_block(event)
            return
        if not self._may_notify(event.level) or not self._popup_allowed(event):
            return
        source = self._source(event)
        if (event.level == ThreatLevel.DANGEROUS and event.type in _BLOCKABLE
                and source and getattr(self.cfg, "auto_block", True)):
            # Hold it for the block that is about to follow.
            self._pending_popups[source] = event
            QTimer.singleShot(_COALESCE_MS, lambda s=source: self._flush_popup(s))
            return
        self._show_popup(event)

    # ── notifications ────────────────────────────────────────────────────

    @staticmethod
    def _source(event: Event) -> str:
        data = event.data or {}
        return str(data.get("src") or data.get("ip") or "")

    def _context_for(self, event: Event) -> str:
        """Clicking a popup opens the page that explains it: the dossier when
        one was filed for this source, the event list otherwise. DNS leaks,
        downgrades and certificate changes have no attacker to file."""
        from maze.core.incident import dossier_source
        return "threats" if dossier_source(event) else "events"

    def _popup_title(self, event: Event, key: str) -> str:
        return self.state.t(key).format(
            kind=self.state.t(f"evtype_{event.type.value}"))

    def _show_popup(self, event: Event) -> None:
        if event.level == ThreatLevel.DANGEROUS:
            self._tray.notify_danger(
                self._popup_title(event, "notif_title_danger"), event.message,
                context=self._context_for(event))
        else:
            self._tray.notify_warning(
                self._popup_title(event, "notif_title_warn"), event.message,
                context=self._context_for(event))

    def _flush_popup(self, source: str) -> None:
        """No block followed in time (auto-block off, refused, or the source
        is infrastructure): show the attack as it is."""
        event = self._pending_popups.pop(source, None)
        if event is not None:
            self._show_popup(event)

    def _on_auto_block(self, event: Event) -> None:
        source = self._source(event)
        attack = self._pending_popups.pop(source, None)
        if attack is not None:
            # One attack, one notification: what happened, and that it was
            # stopped. The held popup already passed the damping checks.
            self._tray.notify_danger(
                self._popup_title(attack, "notif_title_blocked"),
                f"{attack.message}\n{self.state.t('notif_blocked_body')}",
                context="threats")
            return
        if self._may_notify(ThreatLevel.DANGEROUS) and self._popup_allowed(event):
            self._tray.notify_danger(
                self.state.t("notif_title_blocked").format(
                    kind=self.state.t("evtype_ip_blocked")),
                event.message, context="threats")

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
    #
    # The key includes the level, so an escalation (a scan that grows from
    # suspicious to dangerous) is announced rather than taken for a repeat;
    # and the burst budget is per level, so a run of suspicious popups can
    # never use up the room a dangerous one needs.
    _POPUP_REPEAT = 600.0
    _POPUP_WINDOW = 60.0
    _POPUP_BURST = 3

    def _popup_allowed(self, event: Event) -> bool:
        data = event.data or {}
        source = (data.get("src") or data.get("ip") or data.get("mac")
                  or data.get("hostname") or data.get("domain")
                  or data.get("bssid") or data.get("process") or "")
        key = (event.type, event.level, str(source))
        now = time.monotonic()
        if now - self._popup_last.get(key, -self._POPUP_REPEAT) < self._POPUP_REPEAT:
            return False
        recent = [t for t in self._popup_times.get(event.level, [])
                  if now - t < self._POPUP_WINDOW]
        self._popup_times[event.level] = recent
        if len(recent) >= self._POPUP_BURST:
            return False
        self._popup_last[key] = now
        recent.append(now)
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
        self._sync_tray()

    def _notifications_on(self) -> bool:
        """False when the user chose "Off": then nothing pops up at all —
        threats, new devices and profile switches alike."""
        return str(getattr(self.cfg, "notify_min_level", "dangerous")).lower() != "off"

    def _may_notify(self, level: ThreatLevel) -> bool:
        """Whether ``level`` is allowed to raise a desktop popup.

        The dashboard event list always gets the event; this gates only the
        tray notification, per cfg.notify_min_level ("dangerous" | "suspicious"
        | "off"). Unknown values fall back to the default rather than silently
        muting alerts.
        """
        if not self._notifications_on():
            return False
        setting = str(getattr(self.cfg, "notify_min_level", "dangerous")).lower()
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
        self._sync_tray()

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
                self.cfg.profile = f"custom:{getattr(p, 'name', '')}"
                save_config(self.cfg)
                asyncio.ensure_future(self._apply_custom_profile(p))
        self._sync_tray()
        self.dash_view.refresh()

    async def _apply_custom_profile(self, p) -> None:
        await self.engine.apply_custom_profile(p)

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
        # Counted from the events themselves: matching the level column's
        # text ("danger" in it) found nothing once the interface was Turkish.
        counts = self.event_list.level_counts()
        dangerous = counts.get(ThreatLevel.DANGEROUS, 0)
        suspicious = counts.get(ThreatLevel.SUSPICIOUS, 0)
        total = sum(counts.values())

        shield_up = getattr(self, "_shield_left_up", False)
        if total == 0 and not shield_up:
            QApplication.instance().quit()
            return

        t = self.state.t
        dlg = QDialog(self)
        dlg.setWindowTitle(t("sum_title"))
        dlg.setFixedWidth(320)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        title = QLabel(t("sum_title"))
        title.setStyleSheet("font-size: 15px; font-weight: bold;")
        layout.addWidget(title)

        for label, value, color in [
            (t("sum_total"),  str(total),      ""),
            (t("threat_dangerous").title(),  str(dangerous),
             THREAT_COLORS["dangerous"] if dangerous else ""),
            (t("threat_suspicious").title(), str(suspicious),
             THREAT_COLORS["suspicious"] if suspicious else ""),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(label + ":")
            lbl.setObjectName("muted")
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
            note.setObjectName("muted")
            layout.addWidget(note)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btns.accepted.connect(dlg.accept)
        layout.addWidget(btns)

        dlg.exec()
        QApplication.instance().quit()

    def _on_theme_changed(self, theme: str) -> None:
        app = QApplication.instance()
        if app:
            app.setStyleSheet(get_stylesheet(theme))

    # ── i18n ─────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self.state
        self.profile_label.setText(s.t("profile_label").upper())
        self._logo_sub.setText(s.t("app_tagline"))
        self._reset_btn.setToolTip(s.t("tip_reset_threat"))
        self._min_btn.setToolTip(s.t("tip_minimize"))
        self._max_btn.setToolTip(s.t("tip_maximize"))
        self._close_btn.setToolTip(s.t("tip_close_tray"))

        self.profile_combo.blockSignals(True)
        for i, (_, i18n_key) in enumerate(_PROFILES):
            self.profile_combo.setItemText(i, s.t(i18n_key))
        self.profile_combo.blockSignals(False)

        for btn, (_attr, title_key, _sub) in zip(self._nav, _PAGES):
            btn.setText(s.t(title_key))
        self._on_page_changed(self.tabs.currentIndex())
        self._sync_tray()
