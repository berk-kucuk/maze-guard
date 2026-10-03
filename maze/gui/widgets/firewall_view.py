"""Firewall page — the drop rules Maze Guard holds, and adding/removing them."""
import asyncio
import ipaddress

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from maze.gui.theme import THREAT_COLORS
from maze.gui.widgets.common import (
    attach_empty_state, card, chip, set_chip, setup_table,
)


class FirewallView(QWidget):
    def __init__(self, state, engine):
        super().__init__()
        self._state = state
        self._engine = engine
        self._build_ui()
        state.language_changed.connect(self.retranslate)
        self.retranslate()

        self._timer = QTimer(self)
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    # ── build ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 20)
        root.setSpacing(14)

        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        self._fw_chip = chip()
        self._shield_chip = chip()
        status_row.addWidget(self._fw_chip)
        status_row.addWidget(self._shield_chip)
        self._status_lbl = QLabel()
        self._status_lbl.setObjectName("muted")
        status_row.addWidget(self._status_lbl, 1)
        self._flush_btn = QPushButton()
        self._flush_btn.setObjectName("danger")
        self._flush_btn.clicked.connect(self._flush_all)
        status_row.addWidget(self._flush_btn)
        root.addLayout(status_row)

        panels = QHBoxLayout()
        panels.setSpacing(14)
        panels.addWidget(self._build_ip_panel(), 3)
        panels.addWidget(self._build_port_panel(), 2)
        root.addLayout(panels, 1)

    def _build_ip_panel(self) -> QWidget:
        frame, body, self._ip_title = card()
        self._ip_hint = QLabel()
        self._ip_hint.setObjectName("muted")
        self._ip_hint.setWordWrap(True)
        body.addWidget(self._ip_hint)

        self._ip_table = QTableWidget(0, 3)
        setup_table(self._ip_table, stretch=0, fit=(1,), fixed={2: 140})
        self._ip_table.setStyleSheet("QTableWidget { border: none; }")
        self._ip_empty = attach_empty_state(self._ip_table, "")
        body.addWidget(self._ip_table, 1)

        add_row = QHBoxLayout()
        self._ip_input = QLineEdit()
        self._ip_input.returnPressed.connect(self._add_ip)
        add_row.addWidget(self._ip_input, 1)
        self._ip_btn = QPushButton()
        self._ip_btn.setObjectName("primary")
        self._ip_btn.clicked.connect(self._add_ip)
        add_row.addWidget(self._ip_btn)
        body.addLayout(add_row)
        return frame

    def _build_port_panel(self) -> QWidget:
        frame, body, self._port_title = card()
        self._port_hint = QLabel()
        self._port_hint.setObjectName("muted")
        self._port_hint.setWordWrap(True)
        body.addWidget(self._port_hint)

        self._port_table = QTableWidget(0, 3)
        setup_table(self._port_table, stretch=0, fit=(1,), fixed={2: 140})
        self._port_table.setStyleSheet("QTableWidget { border: none; }")
        self._port_empty = attach_empty_state(self._port_table, "")
        body.addWidget(self._port_table, 1)

        add_row = QHBoxLayout()
        self._port_input = QLineEdit()
        self._port_input.setMaximumWidth(140)
        self._port_input.returnPressed.connect(self._add_port)
        add_row.addWidget(self._port_input)
        self._proto_combo = QComboBox()
        self._proto_combo.setMinimumWidth(90)
        self._proto_combo.addItem("TCP", "tcp")
        self._proto_combo.addItem("UDP", "udp")
        self._proto_combo.addItem("TCP + UDP", "both")
        add_row.addWidget(self._proto_combo)
        add_row.addStretch()
        self._port_btn = QPushButton()
        self._port_btn.setObjectName("primary")
        self._port_btn.clicked.connect(self._add_port)
        add_row.addWidget(self._port_btn)
        body.addLayout(add_row)
        return frame

    # ── refresh ────────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        # Each refresh is a firewall-cmd round trip through the helper — not
        # worth it while hidden (tray, or another page). showEvent catches up.
        if not self.isVisible():
            return
        asyncio.ensure_future(self._async_refresh())

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh()

    async def _async_refresh(self) -> None:
        s = self._state
        state = await self._engine.firewall_state()
        rules = state.rules or {}
        if not state.installed:
            set_chip(self._fw_chip, s.t("fwv_backend_missing"), "#8b919a")
        elif state.running:
            set_chip(self._fw_chip, "firewalld · " + s.t("status_running"),
                     THREAT_COLORS["safe"])
        else:
            set_chip(self._fw_chip, "firewalld · " + s.t("status_stopped"),
                     THREAT_COLORS["dangerous"])
        if state.running:
            set_chip(self._shield_chip,
                     s.t("module_firewall") + " · " +
                     s.t("status_active" if state.incoming_blocked else "status_inactive"),
                     THREAT_COLORS["safe"] if state.incoming_blocked
                     else THREAT_COLORS["suspicious"])
        else:
            self._shield_chip.setVisible(False)
        if state.zone:
            self._status_lbl.setText(f"{s.t('fw_detail_zone')}: {state.zone}")
        self._populate_ip_table(rules.get("ips", []), rules.get("macs", []))
        self._populate_port_table(rules.get("ports_tcp", []), rules.get("ports_udp", []))
        for w in (self._ip_btn, self._port_btn, self._flush_btn):
            w.setEnabled(bool(state.running))

    def _unblock_button(self, action) -> QPushButton:
        btn = QPushButton(self._state.t("fwv_unblock"))
        btn.setStyleSheet("padding: 2px 10px; min-height: 0; margin: 3px 6px;")
        btn.clicked.connect(lambda _: asyncio.ensure_future(action()))
        return btn

    def _populate_ip_table(self, ips: list[str], macs: list[str] = ()) -> None:
        # MAC blocks are listed too: auto-block adds one next to every IP
        # block, and a drop rule the interface does not show is a silent block.
        s = self._state
        rows = [(ip, s.t("fwv_kind_ip"), ip, self._unblock_ip) for ip in ips]
        rows += [(mac, s.t("fwv_kind_mac"), mac, self._unblock_mac) for mac in macs]
        self._ip_table.setRowCount(len(rows))
        for r, (text, kind, key, action) in enumerate(rows):
            self._ip_table.setItem(r, 0, QTableWidgetItem(text))
            self._ip_table.setItem(r, 1, QTableWidgetItem(kind))
            self._ip_table.setCellWidget(
                r, 2, self._unblock_button(lambda k=key, a=action: a(k)))
        self._ip_empty.sync()

    def _populate_port_table(self, tcp_ports: list[int], udp_ports: list[int]) -> None:
        rows = [(p, "tcp") for p in tcp_ports] + [(p, "udp") for p in udp_ports]
        self._port_table.setRowCount(len(rows))
        for r, (port, proto) in enumerate(rows):
            self._port_table.setItem(r, 0, QTableWidgetItem(str(port)))
            self._port_table.setItem(r, 1, QTableWidgetItem(proto.upper()))
            self._port_table.setCellWidget(
                r, 2, self._unblock_button(
                    lambda p=port, pr=proto: self._unblock_port(p, pr)))
        self._port_empty.sync()

    # ── actions ────────────────────────────────────────────────────────────

    def _say(self, text: str) -> None:
        self._status_lbl.setText(text)

    def _add_ip(self) -> None:
        s = self._state
        ip = self._ip_input.text().strip()
        if not ip:
            return
        try:
            net = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            self._say(s.t("fwv_invalid_ip").format(ip=ip))
            return
        # The helper refuses anything broader (it would cut this machine off).
        if net.prefixlen < (8 if net.version == 4 else 32):
            self._say(s.t("fwv_too_broad").format(ip=ip))
            return
        self._ip_input.clear()
        asyncio.ensure_future(self._block_ip(ip))

    def _add_port(self) -> None:
        s = self._state
        port_str = self._port_input.text().strip()
        if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
            self._say(s.t("fwv_invalid_port"))
            return
        proto = self._proto_combo.currentData()
        self._port_input.clear()
        asyncio.ensure_future(self._block_port(int(port_str), proto))

    async def _done(self, ok: bool, ok_text: str, fail_text: str) -> None:
        if ok:
            self._say(ok_text)
        else:
            err = self._engine.firewall_error()
            self._say(fail_text + (f" — {err}" if err else ""))
        await self._async_refresh()

    async def _block_ip(self, ip: str) -> None:
        ok = await self._engine.block_ip(ip)
        s = self._state
        await self._done(ok, s.t("fwv_blocked").format(what=ip),
                         s.t("fwv_failed").format(what=ip))

    async def _unblock_ip(self, ip: str) -> None:
        ok = await self._engine.unblock_ip(ip)
        s = self._state
        await self._done(ok, s.t("fwv_unblocked").format(what=ip),
                         s.t("fwv_failed").format(what=ip))

    async def _unblock_mac(self, mac: str) -> None:
        ok = await self._engine.unblock_mac(mac)
        s = self._state
        await self._done(ok, s.t("fwv_unblocked").format(what=mac),
                         s.t("fwv_failed").format(what=mac))

    async def _block_port(self, port: int, proto: str) -> None:
        protos = ("tcp", "udp") if proto == "both" else (proto,)
        ok = True
        for pr in protos:
            ok = await self._engine.block_port(port, pr) and ok
        s = self._state
        what = f"{port}/{'+'.join(p.upper() for p in protos)}"
        await self._done(ok, s.t("fwv_blocked").format(what=what),
                         s.t("fwv_failed").format(what=what))

    async def _unblock_port(self, port: int, proto: str) -> None:
        ok = await self._engine.unblock_port(port, proto)
        s = self._state
        what = f"{port}/{proto.upper()}"
        await self._done(ok, s.t("fwv_unblocked").format(what=what),
                         s.t("fwv_failed").format(what=what))

    def _flush_all(self) -> None:
        s = self._state
        answer = QMessageBox.question(self, s.t("fwv_clear"), s.t("fwv_clear_confirm"))
        if answer != QMessageBox.StandardButton.Yes:
            return
        asyncio.ensure_future(self._async_flush())

    async def _async_flush(self) -> None:
        await self._engine.flush_fw()
        self._say(self._state.t("fwv_cleared"))
        await self._async_refresh()

    # ── i18n ───────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._ip_title.setText(s.t("fwv_sources").upper())
        self._ip_hint.setText(s.t("fwv_sources_hint"))
        self._port_title.setText(s.t("fwv_ports").upper())
        self._port_hint.setText(s.t("fwv_ports_hint"))
        self._ip_table.setHorizontalHeaderLabels(
            [s.t("fwv_address"), s.t("fwv_kind"), ""])
        self._port_table.setHorizontalHeaderLabels(
            [s.t("dash_port"), s.t("dash_proto"), ""])
        self._ip_input.setPlaceholderText(s.t("fwv_ip_placeholder"))
        self._port_input.setPlaceholderText(s.t("fwv_port_placeholder"))
        self._ip_btn.setText(s.t("fwv_block"))
        self._port_btn.setText(s.t("fwv_block"))
        self._flush_btn.setText(s.t("fwv_clear"))
        self._ip_empty.label.setText(s.t("fwv_sources_empty"))
        self._port_empty.label.setText(s.t("fwv_ports_empty"))
        self._refresh()
