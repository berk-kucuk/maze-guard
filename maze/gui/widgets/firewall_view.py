import asyncio
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QSplitter, QSizePolicy,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    lbl = QLabel(title.upper())
    lbl.setObjectName("card_title")
    layout.addWidget(lbl)
    return frame, layout


def _table(cols: list[str], stretch_col: int = 0) -> QTableWidget:
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    t.horizontalHeader().setStretchLastSection(False)
    t.horizontalHeader().setSectionResizeMode(stretch_col, QHeaderView.ResizeMode.Stretch)
    return t


class FirewallView(QWidget):
    def __init__(self, state, engine):
        super().__init__()
        self._state = state
        self._engine = engine
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        QTimer.singleShot(200, self._refresh)

    # ── build ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        # Status bar
        status_row = QHBoxLayout()
        self._status_lbl = QLabel()
        self._status_lbl.setStyleSheet("font-size: 12px; color: #888;")
        status_row.addWidget(self._status_lbl)
        status_row.addStretch()
        flush_btn = QPushButton("Clear All Rules")
        flush_btn.setFixedWidth(130)
        flush_btn.clicked.connect(self._flush_all)
        status_row.addWidget(flush_btn)
        root.addLayout(status_row)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(6)

        splitter.addWidget(self._build_ip_panel())
        splitter.addWidget(self._build_port_panel())
        splitter.setSizes([320, 280])

        root.addWidget(splitter)

    def _build_ip_panel(self) -> QFrame:
        card, layout = _card("Blocked IPs")

        self._ip_table = _table(["IP Address", "Remove"], stretch_col=0)
        self._ip_table.setColumnWidth(1, 80)
        self._ip_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        layout.addWidget(self._ip_table)

        add_row = QHBoxLayout()
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("e.g. 192.168.0.99 or 10.0.0.0/24")
        self._ip_input.returnPressed.connect(self._add_ip)
        add_row.addWidget(self._ip_input)
        btn = QPushButton("Block IP")
        btn.setFixedWidth(90)
        btn.clicked.connect(self._add_ip)
        add_row.addWidget(btn)
        layout.addLayout(add_row)
        return card

    def _build_port_panel(self) -> QFrame:
        card, layout = _card("Blocked Ports")

        self._port_table = _table(["Port", "Protocol", "Remove"], stretch_col=0)
        self._port_table.setColumnWidth(1, 70)
        self._port_table.setColumnWidth(2, 80)
        self._port_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._port_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        layout.addWidget(self._port_table)

        add_row = QHBoxLayout()
        self._port_input = QLineEdit()
        self._port_input.setPlaceholderText("Port number (e.g. 22)")
        self._port_input.setMaximumWidth(200)
        self._port_input.returnPressed.connect(self._add_port)
        add_row.addWidget(self._port_input)
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["TCP", "UDP", "Both"])
        self._proto_combo.setFixedWidth(80)
        add_row.addWidget(self._proto_combo)
        btn = QPushButton("Block Port")
        btn.setFixedWidth(100)
        btn.clicked.connect(self._add_port)
        add_row.addWidget(btn)
        add_row.addStretch()
        layout.addLayout(add_row)
        return card

    # ── refresh ────────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        # Each refresh is a firewall-cmd round trip through the helper — not
        # worth it while hidden (tray, or another tab). showEvent catches up.
        if not self.isVisible():
            return
        asyncio.ensure_future(self._async_refresh())

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh()

    async def _async_refresh(self) -> None:
        rules = await self._engine.list_fw_rules()
        self._populate_ip_table(rules.get("ips", []))
        self._populate_port_table(
            rules.get("ports_tcp", []),
            rules.get("ports_udp", []),
        )
        total = len(rules.get("ips", [])) + len(rules.get("ports_tcp", [])) + len(rules.get("ports_udp", []))
        self._status_lbl.setText(f"{total} active rule{'s' if total != 1 else ''}")

    def _populate_ip_table(self, ips: list[str]) -> None:
        self._ip_table.setRowCount(0)
        for ip in ips:
            row = self._ip_table.rowCount()
            self._ip_table.insertRow(row)
            self._ip_table.setItem(row, 0, QTableWidgetItem(ip))
            btn = QPushButton("Unblock")
            btn.setFixedHeight(24)
            btn.setStyleSheet("font-size: 11px; padding: 0 8px;")
            btn.clicked.connect(lambda _, i=ip: asyncio.ensure_future(self._unblock_ip(i)))
            self._ip_table.setCellWidget(row, 1, btn)

    def _populate_port_table(self, tcp_ports: list[int], udp_ports: list[int]) -> None:
        self._port_table.setRowCount(0)
        for port in tcp_ports:
            self._add_port_row(port, "TCP")
        for port in udp_ports:
            self._add_port_row(port, "UDP")

    def _add_port_row(self, port: int, proto: str) -> None:
        row = self._port_table.rowCount()
        self._port_table.insertRow(row)
        self._port_table.setItem(row, 0, QTableWidgetItem(str(port)))
        self._port_table.setItem(row, 1, QTableWidgetItem(proto))
        btn = QPushButton("Unblock")
        btn.setFixedHeight(24)
        btn.setStyleSheet("font-size: 11px; padding: 0 8px;")
        btn.clicked.connect(
            lambda _, p=port, pr=proto.lower(): asyncio.ensure_future(self._unblock_port(p, pr))
        )
        self._port_table.setCellWidget(row, 2, btn)

    # ── actions ────────────────────────────────────────────────────────────

    def _add_ip(self) -> None:
        ip = self._ip_input.text().strip()
        if not ip:
            return
        # Basic validation
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", ip):
            self._status_lbl.setText(f"Invalid IP: {ip}")
            return
        self._ip_input.clear()
        asyncio.ensure_future(self._block_ip(ip))

    def _add_port(self) -> None:
        port_str = self._port_input.text().strip()
        if not port_str.isdigit():
            self._status_lbl.setText("Invalid port number")
            return
        port = int(port_str)
        if not 1 <= port <= 65535:
            self._status_lbl.setText("Port must be 1–65535")
            return
        proto = self._proto_combo.currentText().lower()
        self._port_input.clear()
        asyncio.ensure_future(self._block_port(port, proto))

    async def _block_ip(self, ip: str) -> None:
        ok = await self._engine.block_ip(ip)
        self._status_lbl.setText(f"Blocked {ip}" if ok else f"Failed to block {ip}")
        await self._async_refresh()

    async def _unblock_ip(self, ip: str) -> None:
        ok = await self._engine.unblock_ip(ip)
        self._status_lbl.setText(f"Unblocked {ip}" if ok else f"Failed to unblock {ip}")
        await self._async_refresh()

    async def _block_port(self, port: int, proto: str) -> None:
        if proto == "both":
            ok1 = await self._engine.block_port(port, "tcp")
            ok2 = await self._engine.block_port(port, "udp")
            ok = ok1 and ok2
        else:
            ok = await self._engine.block_port(port, proto)
        self._status_lbl.setText(
            f"Blocked port {port}/{proto.upper()}" if ok else f"Failed to block port {port}"
        )
        await self._async_refresh()

    async def _unblock_port(self, port: int, proto: str) -> None:
        ok = await self._engine.unblock_port(port, proto)
        self._status_lbl.setText(
            f"Unblocked port {port}/{proto.upper()}" if ok else f"Failed"
        )
        await self._async_refresh()

    def _flush_all(self) -> None:
        asyncio.ensure_future(self._async_flush())

    async def _async_flush(self) -> None:
        await self._engine.flush_fw()
        self._status_lbl.setText("All rules cleared")
        await self._async_refresh()
