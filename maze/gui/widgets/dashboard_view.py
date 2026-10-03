"""
Overview page — the one screen that should answer "am I OK?" at a glance.

The previous version was three status cards, a verbatim `firewall-cmd
--list-all` dump and a scan table: the dump repeated the Firewall page, the
scan table repeated the Threats page, and none of it said in words whether
anything needed doing. This page leads with that sentence, then the numbers
behind it, each of which opens the page that explains it.
"""
import asyncio
from collections import deque

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QMenu, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)
from PyQt6.QtGui import QColor

from maze.core.events import Event, ThreatLevel
from maze.gui.theme import THREAT_COLORS
from maze.gui.widgets.common import (
    StatTile, attach_empty_state, card, chip, set_chip, setup_table,
)
from maze.utils.network_info import get_interface_info, get_open_ports

_RECENT = 7
_GREY = "#8b919a"
# Listening addresses that only this machine can reach.
_LOCAL_PREFIXES = ("127.", "[::1]", "::1", "localhost")


def _fmt_speed(bps: int) -> str:
    if bps < 1024:
        return f"{bps} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    return f"{bps / 1024 / 1024:.1f} MB/s"


def _read_iface_bytes(iface: str) -> tuple[int, int] | None:
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                name, _, rest = line.partition(":")
                if name.strip() == iface and rest:
                    parts = rest.split()
                    return int(parts[0]), int(parts[8])  # rx_bytes, tx_bytes
    except Exception:
        pass
    return None


def _is_local(address: str) -> bool:
    return address.startswith(_LOCAL_PREFIXES)


class _KV(QGridLayout):
    """Two-column key/value list."""

    def __init__(self):
        super().__init__()
        self.setContentsMargins(0, 0, 0, 0)
        self.setHorizontalSpacing(16)
        self.setVerticalSpacing(7)
        self.setColumnStretch(1, 1)
        self._keys: dict[str, QLabel] = {}
        self._vals: dict[str, QWidget] = {}

    def add(self, name: str, widget: QWidget | None = None) -> QWidget:
        row = len(self._keys)
        key = QLabel()
        key.setObjectName("card_key")
        val = widget or QLabel("—")
        if isinstance(val, QLabel) and widget is None:
            val.setObjectName("card_value")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.addWidget(key, row, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.addWidget(val, row, 1, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._keys[name], self._vals[name] = key, val
        return val

    def key(self, name: str, text: str) -> None:
        self._keys[name].setText(text)

    def value(self, name: str) -> QWidget:
        return self._vals[name]

    def show_row(self, name: str, visible: bool) -> None:
        self._keys[name].setVisible(visible)
        self._vals[name].setVisible(visible)


class DashboardView(QWidget):
    def __init__(self, state, engine, cfg, navigate=None):
        super().__init__()
        self._state = state
        self._engine = engine
        self._cfg = cfg
        self._navigate = navigate or (lambda _ctx: None)
        self._level = ThreatLevel.SAFE
        self._event_count_today = 0
        self._recent: deque[Event] = deque(maxlen=_RECENT)
        self._fw_state = None
        self._busy = False

        self._build_ui()
        state.language_changed.connect(self.retranslate)

        self._timer = QTimer(self)
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

        self._bw_prev: tuple[int, int] | None = None
        self._bw_timer = QTimer(self)
        self._bw_timer.setInterval(1000)
        self._bw_timer.timeout.connect(self._update_bandwidth)
        self._bw_timer.start()

        self.retranslate()

    # ── build ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        root.addWidget(self._build_hero())

        tiles = QHBoxLayout()
        tiles.setSpacing(14)
        self._tile_threats = StatTile(lambda: self._navigate("threats"))
        self._tile_blocked = StatTile(lambda: self._navigate("firewall"))
        self._tile_devices = StatTile(lambda: self._navigate("devices"))
        self._tile_events = StatTile(lambda: self._navigate("events"))
        for t in (self._tile_threats, self._tile_blocked,
                  self._tile_devices, self._tile_events):
            tiles.addWidget(t)
        root.addLayout(tiles)

        mid = QHBoxLayout()
        mid.setSpacing(14)
        mid.addWidget(self._build_network_card(), 1)
        mid.addWidget(self._build_protection_card(), 1)
        root.addLayout(mid)

        low = QHBoxLayout()
        low.setSpacing(14)
        low.addWidget(self._build_recent_card(), 3)
        low.addWidget(self._build_ports_card(), 2)
        root.addLayout(low, 1)

    def _build_hero(self) -> QFrame:
        hero = QFrame()
        hero.setObjectName("hero")
        lay = QHBoxLayout(hero)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(16)
        self._hero_icon = QLabel()
        self._hero_icon.setFixedSize(46, 46)
        self._hero_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._hero_icon)
        text = QVBoxLayout()
        text.setSpacing(3)
        self._hero_title = QLabel()
        self._hero_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        self._hero_body = QLabel()
        self._hero_body.setObjectName("muted")
        self._hero_body.setWordWrap(True)
        text.addWidget(self._hero_title)
        text.addWidget(self._hero_body)
        lay.addLayout(text, 1)
        self._hero_btn = QPushButton()
        self._hero_btn.setObjectName("primary")
        self._hero_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._hero_btn.clicked.connect(self._on_hero_action)
        self._hero_action = ""
        lay.addWidget(self._hero_btn)
        return hero

    def _build_network_card(self) -> QFrame:
        frame, body, self._net_title = card()
        head = QHBoxLayout()
        head.addWidget(self._net_title)
        head.addStretch()
        self._net_chip = chip()
        head.addWidget(self._net_chip)
        body.insertLayout(0, head)
        self._net = _KV()
        for name in ("iface", "network", "ip", "gateway", "mac", "vpn", "traffic"):
            self._net.add(name)
        body.addLayout(self._net)
        body.addStretch()
        return frame

    def _build_protection_card(self) -> QFrame:
        frame, body, self._prot_title = card()
        head = QHBoxLayout()
        head.addWidget(self._prot_title)
        head.addStretch()
        self._prot_link = QPushButton()
        self._prot_link.setObjectName("link")
        self._prot_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self._prot_link.clicked.connect(lambda: self._navigate("protection"))
        head.addWidget(self._prot_link)
        body.insertLayout(0, head)
        self._prot = _KV()
        self._prot.add("profile")
        for name in ("firewall", "shield", "helper"):
            self._prot.add(name, chip())
        self._prot.add("modules")
        self._prot.add("rules")
        body.addLayout(self._prot)
        body.addStretch()
        return frame

    def _build_recent_card(self) -> QFrame:
        frame, body, self._recent_title = card()
        head = QHBoxLayout()
        head.addWidget(self._recent_title)
        head.addStretch()
        self._recent_link = QPushButton()
        self._recent_link.setObjectName("link")
        self._recent_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self._recent_link.clicked.connect(lambda: self._navigate("events"))
        head.addWidget(self._recent_link)
        body.insertLayout(0, head)

        self._recent_table = QTableWidget(0, 3)
        setup_table(self._recent_table, stretch=2, fit=(0, 1))
        self._recent_table.horizontalHeader().setVisible(False)
        self._recent_table.setAlternatingRowColors(False)
        self._recent_table.setStyleSheet("QTableWidget { border: none; }")
        self._recent_table.cellDoubleClicked.connect(
            lambda *_: self._navigate("events"))
        self._recent_empty = attach_empty_state(self._recent_table, "")
        body.addWidget(self._recent_table, 1)
        return frame

    def _build_ports_card(self) -> QFrame:
        frame, body, self._ports_title = card()
        self._ports_hint = QLabel()
        self._ports_hint.setObjectName("muted")
        self._ports_hint.setWordWrap(True)
        body.addWidget(self._ports_hint)
        self._ports = QTableWidget(0, 3)
        setup_table(self._ports, stretch=1, fit=(0, 2))
        self._ports.setStyleSheet("QTableWidget { border: none; }")
        self._ports.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._ports.customContextMenuRequested.connect(self._ports_context_menu)
        self._ports_empty = attach_empty_state(self._ports, "")
        body.addWidget(self._ports, 1)
        return frame

    # ── refresh ───────────────────────────────────────────────────────────

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # The byte counters kept moving while we were hidden — a delta across
        # that gap would show as one absurd burst.
        self._bw_prev = None
        self.refresh()

    def refresh(self) -> None:
        # Not while hidden (tray, or another page): this asks the firewall and
        # runs `ip`/`ss`. showEvent refreshes when the page comes back.
        if not self.isVisible() or self._busy:
            return
        asyncio.ensure_future(self._refresh_async())

    def _iface(self) -> str:
        identity = getattr(self._engine, "identity", None)
        return (getattr(identity, "interface", "") or self._cfg.interface or "")

    async def _refresh_async(self) -> None:
        self._busy = True
        try:
            # ip/iw/ss are subprocesses: off the GUI thread, or every refresh
            # froze the window for as long as they took.
            info, ports = await asyncio.gather(
                asyncio.to_thread(get_interface_info, self._iface()),
                asyncio.to_thread(get_open_ports))
            self._fw_state = await self._engine.firewall_state()
        except Exception:
            info, ports = None, None
        finally:
            self._busy = False
        if info is not None:
            self._paint_network(info)
        if ports is not None:
            self._paint_ports(ports)
        self._paint_protection()
        self._paint_tiles()
        self._paint_hero()

    def _update_bandwidth(self) -> None:
        if not self.isVisible():
            return
        curr = _read_iface_bytes(self._iface())
        if curr is None:
            return
        if self._bw_prev is not None:
            rx = max(0, curr[0] - self._bw_prev[0])
            tx = max(0, curr[1] - self._bw_prev[1])
            self._net.value("traffic").setText(f"↓ {_fmt_speed(rx)}    ↑ {_fmt_speed(tx)}")
        self._bw_prev = curr

    # ── painting ──────────────────────────────────────────────────────────

    def _paint_network(self, info) -> None:
        s = self._state
        up = info.status == "up" or (info.ip not in ("", "—"))
        set_chip(self._net_chip, s.t("dash_connected" if up else "dash_disconnected"),
                 THREAT_COLORS["safe"] if up else _GREY)
        network = info.ssid or self._network_name()
        values = {"iface": info.name, "network": network or "—", "ip": info.ip,
                  "gateway": info.gateway, "mac": info.mac,
                  "vpn": ", ".join(info.vpn_ifaces)}
        for name, text in values.items():
            self._net.value(name).setText(text or "—")
        self._net.show_row("vpn", bool(info.vpn_ifaces))

    def _network_name(self) -> str:
        """The current network as a person would name it: the Wi-Fi name, or
        "wired network" — a gateway's MAC address means nothing to anyone."""
        net_id = getattr(getattr(self._engine, "identity", None), "network_id", "")
        kind, _, value = net_id.partition(":")
        if kind == "wifi":
            return value
        if kind == "gw":
            return self._state.t("dash_wired")
        return net_id

    def _protection_counts(self) -> tuple[int, int]:
        states = self._engine.module_states()
        # The firewall manager is plumbing, not a protection the user toggles.
        keys = [k for k in states if k != "firewall"]
        return sum(1 for k in keys if states[k]), len(keys)

    def _paint_protection(self) -> None:
        s = self._state
        helper = getattr(self._engine, "helper", None)
        connected = bool(helper and helper.is_connected())
        fw = self._fw_state

        profile = getattr(self._cfg, "profile", "home") or "home"
        if profile.startswith("custom:"):
            profile_text = profile.split(":", 1)[1]
        else:
            profile_text = s.t(f"profile_{profile}")
        self._prot.value("profile").setText(profile_text)

        if fw is None or not fw.installed:
            fw_text, fw_col = s.t("status_unavailable"), _GREY
        elif fw.running:
            fw_text, fw_col = s.t("status_running"), THREAT_COLORS["safe"]
        else:
            fw_text, fw_col = s.t("status_stopped"), THREAT_COLORS["dangerous"]
        set_chip(self._prot.value("firewall"), fw_text, fw_col)

        if fw is not None and fw.running:
            on = fw.incoming_blocked
            set_chip(self._prot.value("shield"),
                     s.t("status_active" if on else "status_inactive"),
                     THREAT_COLORS["safe"] if on else THREAT_COLORS["suspicious"])
        else:
            set_chip(self._prot.value("shield"), s.t("status_unavailable"), _GREY)

        set_chip(self._prot.value("helper"),
                 s.t("dash_helper_ok" if connected else "dash_helper_missing"),
                 THREAT_COLORS["safe"] if connected else THREAT_COLORS["suspicious"])

        active, total = self._protection_counts()
        self._prot.value("modules").setText(
            s.t("dash_modules_fmt").format(active=active, total=total))
        rules = (fw.rules if fw else None) or {}
        n = sum(len(rules.get(k, [])) for k in ("ips", "macs", "ports_tcp", "ports_udp"))
        self._prot.value("rules").setText(
            s.t("dash_rules_fmt").format(n=n) if n else s.t("dash_no_rules"))

    def _paint_tiles(self) -> None:
        incidents = self._engine.incidents
        active = len(incidents.active(60))
        self._tile_threats.set(active, THREAT_COLORS["dangerous"] if active else "")
        fw = self._fw_state
        rules = (fw.rules if fw else None) or {}
        self._tile_blocked.set(len(rules.get("ips", [])) + len(rules.get("macs", [])))
        watcher = self._engine.arp_watcher
        self._tile_devices.set(len(watcher.devices) if watcher else 0)
        self._tile_events.set(self._event_count_today)

    def _paint_hero(self) -> None:
        s = self._state
        helper = getattr(self._engine, "helper", None)
        connected = bool(helper and helper.is_connected())
        fw = self._fw_state
        active, total = self._protection_counts()
        threats = len(self._engine.incidents.active(60))

        if self._level == ThreatLevel.DANGEROUS:
            key, color, action = "danger", THREAT_COLORS["dangerous"], "threats"
        elif self._level == ThreatLevel.SUSPICIOUS:
            key, color, action = "warn", THREAT_COLORS["suspicious"], "events"
        elif not connected:
            key, color, action = "limited", THREAT_COLORS["suspicious"], "settings"
        elif getattr(helper, "outdated", False):
            key, color, action = "outdated", THREAT_COLORS["suspicious"], "settings"
        elif fw is not None and fw.installed and not fw.running:
            key, color, action = "fw_off", THREAT_COLORS["dangerous"], "protection"
        else:
            key, color, action = "ok", THREAT_COLORS["safe"], ""

        network = self._network_name() or "—"
        self._hero_title.setText(s.t(f"hero_{key}_title"))
        self._hero_title.setStyleSheet(
            f"font-size: 18px; font-weight: 700; color: {color};")
        self._hero_body.setText(s.t(f"hero_{key}_body").format(
            active=active, total=total, threats=threats, network=network))
        glyph = {"ok": "✓", "danger": "!", "fw_off": "!"}.get(key, "i")
        c = QColor(color)
        self._hero_icon.setText(glyph)
        self._hero_icon.setStyleSheet(
            f"background-color: rgba({c.red()},{c.green()},{c.blue()},40);"
            f"color: {color}; border-radius: 23px; font-size: 22px; font-weight: 800;")
        self._hero_action = action
        self._hero_btn.setVisible(bool(action))
        if action:
            self._hero_btn.setText(s.t(f"hero_{key}_action"))

    def _on_hero_action(self) -> None:
        if self._hero_action:
            self._navigate(self._hero_action)

    def _paint_ports(self, ports) -> None:
        s = self._state
        self._ports.setRowCount(0)
        # Reachable-from-the-network first: that is the exposure.
        ports = sorted(ports, key=lambda p: (_is_local(p.address), p.port))
        exposed = 0
        for p in ports:
            local = _is_local(p.address)
            exposed += not local
            row = self._ports.rowCount()
            self._ports.insertRow(row)
            port_item = QTableWidgetItem(f"{p.port}/{p.protocol.lower()}")
            port_item.setData(Qt.ItemDataRole.UserRole, (p.port, p.protocol.lower()))
            proc_item = QTableWidgetItem(p.process or "—")
            scope = QTableWidgetItem(s.t("dash_scope_local" if local else "dash_scope_network"))
            scope.setForeground(QColor(_GREY if local else THREAT_COLORS["suspicious"]))
            scope.setToolTip(p.address)
            for col, item in enumerate((port_item, proc_item, scope)):
                self._ports.setItem(row, col, item)
        self._ports_hint.setText(s.t("dash_ports_hint").format(n=exposed))
        self._ports_empty.sync()

    def _paint_recent(self) -> None:
        s = self._state
        self._recent_table.setRowCount(0)
        for event in reversed(self._recent):
            row = self._recent_table.rowCount()
            self._recent_table.insertRow(row)
            when = QTableWidgetItem(event.timestamp.strftime("%H:%M"))
            when.setForeground(QColor(_GREY))
            level = QTableWidgetItem(s.t(f"threat_{event.level.value}"))
            level.setForeground(QColor(THREAT_COLORS[event.level.value]))
            msg = QTableWidgetItem(event.message)
            msg.setToolTip(event.message)
            for col, item in enumerate((when, level, msg)):
                self._recent_table.setItem(row, col, item)
        self._recent_empty.sync()

    # ── context menu ──────────────────────────────────────────────────────

    def _ports_context_menu(self, pos) -> None:
        row = self._ports.rowAt(pos.y())
        item = self._ports.item(row, 0) if row >= 0 else None
        if item is None:
            return
        port, proto = item.data(Qt.ItemDataRole.UserRole)
        s = self._state
        menu = QMenu(self)
        act = menu.addAction(s.t("dash_block_port").format(port=f"{port}/{proto.upper()}"))
        if menu.exec(self._ports.viewport().mapToGlobal(pos)) == act:
            asyncio.ensure_future(self._engine.block_port(port, proto))

    # ── called by the main window ─────────────────────────────────────────

    def add_event(self, event: Event) -> None:
        self._event_count_today += 1
        if event.level != ThreatLevel.SAFE:
            self._recent.append(event)
            self._paint_recent()
        self._tile_events.set(self._event_count_today)

    def increment_event_count(self) -> None:
        self._event_count_today += 1
        self._tile_events.set(self._event_count_today)

    def update_threat_level(self, level: ThreatLevel) -> None:
        self._level = level
        self._paint_hero()

    def reset_threat_level(self) -> None:
        self._level = ThreatLevel.SAFE
        self._event_count_today = 0
        self._tile_events.set(0)
        self._paint_hero()

    # ── i18n ─────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._tile_threats.label.setText(s.t("tile_threats"))
        self._tile_blocked.label.setText(s.t("tile_blocked"))
        self._tile_devices.label.setText(s.t("tile_devices"))
        self._tile_events.label.setText(s.t("tile_events"))
        self._net_title.setText(s.t("dash_network").upper())
        self._prot_title.setText(s.t("dash_protection").upper())
        self._prot_link.setText(s.t("dash_manage") + " →")
        self._recent_title.setText(s.t("dash_recent").upper())
        self._recent_link.setText(s.t("dash_view_all") + " →")
        self._ports_title.setText(s.t("dash_open_ports").upper())
        self._recent_empty.label.setText(s.t("dash_recent_empty"))
        self._ports_empty.label.setText(s.t("dash_no_ports"))
        for name, key in (("iface", "dash_iface"), ("network", "dash_ssid"),
                          ("ip", "dash_ip"), ("gateway", "dash_gateway"),
                          ("mac", "dash_mac"), ("vpn", "dash_vpn"),
                          ("traffic", "dash_traffic")):
            self._net.key(name, s.t(key))
        for name, key in (("profile", "profile_label"), ("firewall", "dash_firewall"),
                          ("shield", "module_firewall"), ("helper", "dash_helper"),
                          ("modules", "dash_modules"), ("rules", "dash_fw_rules")):
            self._prot.key(name, s.t(key))
        self._ports.setHorizontalHeaderLabels(
            [s.t("dash_port"), s.t("dash_process"), s.t("dash_scope")])
        self._paint_tiles()
        self._paint_hero()
        self._paint_protection()
        self._paint_recent()
