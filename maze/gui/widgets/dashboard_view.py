import asyncio
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPlainTextEdit, QGridLayout, QSizePolicy, QMenu,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor

from maze.core.events import ThreatLevel
from maze.gui.theme import THREAT_COLORS
from maze.utils.network_info import (
    get_interface_info, get_open_ports, get_active_physical_interface,
)


# ── helpers ──────────────────────────────────────────────────────────────────

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
                if iface in line:
                    parts = line.split()
                    return int(parts[1]), int(parts[9])  # rx_bytes, tx_bytes
    except Exception:
        pass
    return None


def _lbl(text: str, obj_name: str = "", bold: bool = False) -> QLabel:
    lbl = QLabel(text)
    if obj_name:
        lbl.setObjectName(obj_name)
    if bold:
        lbl.setStyleSheet(lbl.styleSheet() + " font-weight: bold;")
    return lbl


def _dot(color: str, size: int = 10) -> QLabel:
    lbl = QLabel("●")
    lbl.setStyleSheet(f"color: {color}; font-size: {size}px; background: transparent;")
    return lbl


# ── InfoCard ─────────────────────────────────────────────────────────────────

class InfoCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(16, 14, 16, 16)
        self._outer.setSpacing(10)

        self._title_lbl = QLabel()
        self._title_lbl.setObjectName("card_title")
        self._outer.addWidget(self._title_lbl)

        self._rows_layout = QGridLayout()
        self._rows_layout.setContentsMargins(0, 0, 0, 0)
        self._rows_layout.setHorizontalSpacing(12)
        self._rows_layout.setVerticalSpacing(4)
        self._outer.addLayout(self._rows_layout)

        self._outer.addStretch()
        self._row_idx = 0
        self._value_labels: dict[str, QLabel] = {}
        self._dot_labels: dict[str, QLabel] = {}

    def set_title(self, text: str) -> None:
        self._title_lbl.setText(text.upper())

    def add_status_row(self, key: str, dot_color: str, value_text: str) -> None:
        dot = _dot(dot_color, 9)
        self._dot_labels[key] = dot
        val = QLabel(value_text)
        val.setObjectName("card_value")
        val.setStyleSheet("font-size: 15px; font-weight: bold; background: transparent;")
        self._value_labels[key] = val
        self._rows_layout.addWidget(dot, self._row_idx, 0, Qt.AlignmentFlag.AlignVCenter)
        self._rows_layout.addWidget(val, self._row_idx, 1, Qt.AlignmentFlag.AlignVCenter)
        self._row_idx += 1

    def add_kv_row(self, key_text: str, value_text: str, key: str = "") -> None:
        k = QLabel(key_text)
        k.setObjectName("card_key")
        v = QLabel(value_text)
        v.setObjectName("card_value")
        v.setWordWrap(True)
        if key:
            self._value_labels[key] = v
        self._rows_layout.addWidget(k, self._row_idx, 0)
        self._rows_layout.addWidget(v, self._row_idx, 1)
        self._row_idx += 1

    def update_value(self, key: str, text: str) -> None:
        if key in self._value_labels:
            self._value_labels[key].setText(text)

    def update_dot(self, key: str, color: str) -> None:
        if key in self._dot_labels:
            self._dot_labels[key].setStyleSheet(
                f"color: {color}; font-size: 9px; background: transparent;"
            )


# ── TableSection ─────────────────────────────────────────────────────────────

class TableSection(QFrame):
    def __init__(self, cols: int, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        self._title_lbl = QLabel()
        self._title_lbl.setObjectName("card_title")
        layout.addWidget(self._title_lbl)

        self.table = QTableWidget(0, cols)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def set_title(self, text: str) -> None:
        self._title_lbl.setText(text.upper())

    def set_headers(self, headers: list[str]) -> None:
        self.table.setHorizontalHeaderLabels(headers)

    def set_col_width(self, col: int, width: int) -> None:
        self.table.setColumnWidth(col, width)
        self.table.horizontalHeader().setSectionResizeMode(
            col, QHeaderView.ResizeMode.Fixed
        )

    def clear_rows(self) -> None:
        self.table.setRowCount(0)

    def add_row(self, values: list[str], colors: dict[int, str] | None = None) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            if colors and col in colors:
                item.setForeground(QColor(colors[col]))
            self.table.setItem(row, col, item)

    def enable_context_menu(self, callback) -> None:
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(callback)


# ── RulesSection ─────────────────────────────────────────────────────────────

class RulesSection(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        self._title_lbl = QLabel()
        self._title_lbl.setObjectName("card_title")
        layout.addWidget(self._title_lbl)

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        layout.addWidget(self._text)

    def set_title(self, text: str) -> None:
        self._title_lbl.setText(text.upper())

    def set_content(self, text: str) -> None:
        self._text.setPlainText(text)


# ── DashboardView ─────────────────────────────────────────────────────────────

class DashboardView(QWidget):
    def __init__(self, state, engine, cfg):
        super().__init__()
        self._state = state
        self._engine = engine
        self._cfg = cfg
        self._event_count_today = 0

        self._build_ui()
        state.language_changed.connect(self.retranslate)

        self._timer = QTimer(self)
        self._timer.setInterval(5000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

        # Bandwidth monitor — reads /proc/net/dev every second
        self._bw_prev: tuple[int, int] | None = None
        self._bw_timer = QTimer(self)
        self._bw_timer.setInterval(1000)
        self._bw_timer.timeout.connect(self._update_bandwidth)
        self._bw_timer.start()

        # Initial data
        QTimer.singleShot(300, self.refresh)

    # ── build ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._main = QVBoxLayout(self)
        self._main.setContentsMargins(20, 16, 20, 16)
        self._main.setSpacing(14)

        # Row 1 — three info cards
        top_row = QHBoxLayout()
        top_row.setSpacing(14)
        self._net_card    = self._build_net_card()
        self._fw_card     = self._build_fw_card()
        self._threat_card = self._build_threat_card()
        top_row.addWidget(self._net_card)
        top_row.addWidget(self._fw_card)
        top_row.addWidget(self._threat_card)
        self._main.addLayout(top_row, stretch=2)

        # Row 2 — ports + rules
        mid_row = QHBoxLayout()
        mid_row.setSpacing(14)
        self._ports_section = TableSection(3)
        self._ports_section.set_col_width(0, 70)
        self._ports_section.set_col_width(1, 60)
        self._ports_section.enable_context_menu(self._ports_context_menu)
        mid_row.addWidget(self._ports_section, 4)

        self._rules_section = RulesSection()
        mid_row.addWidget(self._rules_section, 6)
        self._main.addLayout(mid_row, stretch=2)

        # Row 3 — scan detection
        self._scan_section = TableSection(3)
        self._scan_section.set_col_width(0, 150)
        self._scan_section.set_col_width(1, 80)
        self._scan_section.enable_context_menu(self._scan_context_menu)
        self._main.addWidget(self._scan_section, stretch=3)

        self.retranslate()

    def _build_net_card(self) -> InfoCard:
        card = InfoCard()
        card.add_status_row("status", THREAT_COLORS["safe"], "—")
        card.add_kv_row("", "", "ip_val")
        card.add_kv_row("", "", "mac_val")
        card.add_kv_row("", "", "gw_val")
        card.add_kv_row("", "", "ssid_val")
        card.add_kv_row("", "", "vpn_val")
        card.add_kv_row("", "", "bw_val")
        return card

    def _build_fw_card(self) -> InfoCard:
        card = InfoCard()
        card.add_status_row("fw_status", "#555555", "—")
        card.add_kv_row("", "", "fw_profile_val")
        card.add_kv_row("", "", "fw_rules_val")
        return card

    def _build_threat_card(self) -> InfoCard:
        card = InfoCard()
        card.add_status_row("threat", THREAT_COLORS["safe"], "—")
        card.add_kv_row("", "", "events_val")
        card.add_kv_row("", "", "scans_val")
        card.add_kv_row("", "", "blocked_val")
        return card

    # ── refresh ───────────────────────────────────────────────────────────

    def refresh(self) -> None:
        self._refresh_network()
        asyncio.ensure_future(self._refresh_firewall())
        self._refresh_ports()
        self._refresh_scan()

    def _update_bandwidth(self) -> None:
        iface = self._cfg.interface
        curr = _read_iface_bytes(iface)
        if curr is None:
            return
        if self._bw_prev is not None:
            rx_bps = max(0, curr[0] - self._bw_prev[0])
            tx_bps = max(0, curr[1] - self._bw_prev[1])
            self._net_card.update_value(
                "bw_val",
                f"↓ {_fmt_speed(rx_bps)}   ↑ {_fmt_speed(tx_bps)}",
            )
        self._bw_prev = curr

    def _refresh_network(self) -> None:
        s = self._state
        iface = get_active_physical_interface()
        info = get_interface_info(iface)
        connected = info.status == "up" or iface != "—"
        dot_color = THREAT_COLORS["safe"] if connected else "#555555"
        status_text = s.t("dash_connected") if connected else s.t("dash_disconnected")

        self._net_card.update_dot("status", dot_color)
        self._net_card.update_value("status", f"{info.name}  {status_text}")
        self._net_card.update_value("ip_val", f"{s.t('dash_ip')}:  {info.ip}")
        self._net_card.update_value("mac_val", f"{s.t('dash_mac')}:  {info.mac}")
        self._net_card.update_value("gw_val", f"{s.t('dash_gateway')}:  {info.gateway}")
        ssid_text = f"{s.t('dash_ssid')}:  {info.ssid}" if info.ssid else ""
        self._net_card.update_value("ssid_val", ssid_text)
        if info.vpn_ifaces:
            vpn_text = f"{s.t('dash_vpn')}:  {', '.join(info.vpn_ifaces)}"
        else:
            vpn_text = ""
        self._net_card.update_value("vpn_val", vpn_text)

    async def _refresh_firewall(self) -> None:
        """Paint the firewall card from the engine's live state.

        Deriving "is the firewall on" from the presence of --list-all output —
        the previous approach — could not tell a stopped firewall apart from an
        unreachable helper, so a card reading "Active" was not evidence of
        anything. The engine answers the question directly.
        """
        s = self._state
        state = await self._engine.firewall_state()
        helper = getattr(self._engine, 'helper', None)

        if not state.installed:
            dot_color = "#555555"
            status_text = (s.t("dash_fw_inactive") if helper
                           else "(needs root)")
        elif not state.running:
            dot_color = THREAT_COLORS["dangerous"]
            status_text = s.t("status_stopped")
        elif state.incoming_blocked:
            dot_color = THREAT_COLORS["safe"]
            status_text = f"{s.t('status_running')} · {s.t('module_firewall')}"
        else:
            dot_color = THREAT_COLORS["suspicious"]
            status_text = s.t("status_running")

        self._fw_card.update_dot("fw_status", dot_color)
        self._fw_card.update_value("fw_status", status_text)
        self._fw_card.update_value(
            "fw_profile_val",
            f"{s.t('dash_fw_profile')}:  {state.zone or s.t('dash_fw_none')}")

        rules = state.rules or {}
        count = (len(rules.get("ips", [])) + len(rules.get("ports_tcp", []))
                 + len(rules.get("ports_udp", [])))
        self._fw_card.update_value(
            "fw_rules_val",
            f"{count} rules active" if count else s.t("dash_no_rules"))

        # The rule pane still shows firewalld's own rendering — it is the
        # authoritative text, and useful to read verbatim. Only ask when there
        # is something to ask: querying a stopped firewalld is a question with a
        # known answer, and one this timer would repeat every few seconds.
        raw = ""
        if state.running and helper and helper.is_connected():
            raw = await helper.fw_list_all()
        elif state.installed and not state.running:
            raw = s.t("status_stopped")
        self._rules_section.set_content(raw or s.t("dash_no_rules"))

    def _refresh_ports(self) -> None:
        s = self._state
        ports = get_open_ports()
        self._ports_section.clear_rows()
        if not ports:
            self._ports_section.add_row([s.t("dash_no_ports"), "", ""])
        else:
            for p in ports:
                addr = p.address.replace("0.0.0.0", "*").replace("[::]", "*")
                self._ports_section.add_row([str(p.port), p.protocol, addr])

    def _refresh_scan(self) -> None:
        s = self._state
        detector = self._engine._modules.get("port_scan")
        self._scan_section.clear_rows()

        if detector is None or "port_scan" not in self._engine._active:
            self._scan_section.add_row([s.t("dash_scan_inactive"), "", ""])
            return

        attempts = detector.scan_attempts
        blocked  = detector.blocked_ips

        total_attempts = sum(attempts.values())
        self._threat_card.update_value("scans_val",
            f"{s.t('dash_attempts')}:  {total_attempts}")
        self._threat_card.update_value("blocked_val",
            f"{s.t('dash_blocked_ips')}:  {len(blocked) or s.t('dash_no_blocked')}")

        if not attempts:
            self._scan_section.add_row([s.t("dash_no_blocked"), "", ""])
        else:
            for ip, count in sorted(attempts.items(), key=lambda x: -x[1]):
                status = "BLOCKED" if ip in blocked else "Monitoring"
                color = THREAT_COLORS["dangerous"] if ip in blocked else THREAT_COLORS["suspicious"]
                self._scan_section.add_row(
                    [ip, str(count), status],
                    colors={2: color},
                )

    # ── context menus ─────────────────────────────────────────────────────

    def _scan_context_menu(self, pos) -> None:
        table = self._scan_section.table
        row = table.rowAt(pos.y())
        if row < 0:
            return
        ip_item = table.item(row, 0)
        if not ip_item:
            return
        ip = ip_item.text()
        if not ip or '.' not in ip:
            return
        menu = QMenu(self)
        act = menu.addAction(f"Block IP  {ip}")
        if menu.exec(table.viewport().mapToGlobal(pos)) == act:
            asyncio.ensure_future(self._engine.block_ip(ip))

    def _ports_context_menu(self, pos) -> None:
        table = self._ports_section.table
        row = table.rowAt(pos.y())
        if row < 0:
            return
        port_item = table.item(row, 0)
        proto_item = table.item(row, 1)
        if not port_item or not port_item.text().isdigit():
            return
        port  = int(port_item.text())
        proto = (proto_item.text() if proto_item else "TCP").lower()
        menu = QMenu(self)
        act_block = menu.addAction(f"Block Port  {port}/{proto.upper()}")
        act_both  = menu.addAction(f"Block Port  {port}/TCP + UDP")
        chosen = menu.exec(table.viewport().mapToGlobal(pos))
        if chosen == act_block:
            asyncio.ensure_future(self._engine.block_port(port, proto))
        elif chosen == act_both:
            asyncio.ensure_future(self._engine.block_port(port, "tcp"))
            asyncio.ensure_future(self._engine.block_port(port, "udp"))

    def increment_event_count(self) -> None:
        self._event_count_today += 1
        self._threat_card.update_value("events_val",
            f"{self._event_count_today} {self._state.t('dash_events_today')}")

    def update_threat_level(self, level: ThreatLevel) -> None:
        color = THREAT_COLORS[level.value]
        self._threat_card.update_dot("threat", color)
        self._threat_card.update_value("threat", self._state.t(f"threat_{level.value}"))

    def reset_threat_level(self) -> None:
        self._event_count_today = 0
        self._threat_card.update_value("events_val", "")
        self._threat_card.update_value("scans_val", "")
        self._threat_card.update_value("blocked_val", "")
        self._threat_card.update_dot("threat", THREAT_COLORS["safe"])
        self._threat_card.update_value("threat", self._state.t("threat_safe"))

    # ── i18n ─────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._net_card.set_title(s.t("dash_network"))
        self._fw_card.set_title(s.t("dash_firewall"))
        self._threat_card.set_title(s.t("dash_threats"))
        self._ports_section.set_title(s.t("dash_open_ports"))
        self._ports_section.set_headers([
            s.t("dash_port"), s.t("dash_proto"), s.t("dash_ip"),
        ])
        self._rules_section.set_title(s.t("dash_fw_rules"))
        self._scan_section.set_title(s.t("dash_scan"))
        self._scan_section.set_headers([
            "IP", s.t("dash_attempts"), s.t("dash_action"),
        ])
