import asyncio
import csv
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QMenu, QPushButton, QLineEdit, QFileDialog, QSplitter,
    QTextEdit,
)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt
from maze.core.events import Event, ThreatLevel
from maze.core.explain import explain
from maze.gui.theme import THREAT_COLORS

_IP_RE   = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_PORT_RE = re.compile(r'→\s*\S+:(\d{2,5})\b')


class EventListWidget(QWidget):
    def __init__(self, state, engine=None):
        super().__init__()
        self._state        = state
        self._engine       = engine
        self._filter_level = None   # None = all
        self._filter_text  = ""
        self._all_events: list[tuple[Event, int]] = []  # (event, row_index)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_filter_bar())

        self._table = QTableWidget(0, 4)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 80)
        self._table.setColumnWidth(1, 110)
        self._table.setColumnWidth(2, 160)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.itemSelectionChanged.connect(self._on_select)

        # A detection nobody can act on has done half a job. Selecting a row
        # says what the observation means and what to do about it, in the same
        # language as the rest of the interface.
        self._explain = QTextEdit()
        self._explain.setReadOnly(True)
        self._explain.setStyleSheet("font-size: 12px;")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(6)
        splitter.addWidget(self._table)
        splitter.addWidget(self._explain)
        splitter.setSizes([520, 190])
        layout.addWidget(splitter)

        state.language_changed.connect(self.retranslate)
        self.retranslate()

    def _build_filter_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(40)
        row = QHBoxLayout(bar)
        row.setContentsMargins(8, 4, 8, 4)
        row.setSpacing(6)

        self._btn_all  = QPushButton("All")
        self._btn_susp = QPushButton("Suspicious")
        self._btn_dang = QPushButton("Dangerous")
        for btn in (self._btn_all, self._btn_susp, self._btn_dang):
            btn.setFixedHeight(28)
            btn.setCheckable(True)
        self._btn_all.setChecked(True)

        self._btn_all.clicked.connect(lambda: self._set_level_filter(None))
        self._btn_susp.clicked.connect(lambda: self._set_level_filter(ThreatLevel.SUSPICIOUS))
        self._btn_dang.clicked.connect(lambda: self._set_level_filter(ThreatLevel.DANGEROUS))

        row.addWidget(self._btn_all)
        row.addWidget(self._btn_susp)
        row.addWidget(self._btn_dang)
        row.addSpacing(12)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search events…")
        self._search.setFixedHeight(28)
        self._search.textChanged.connect(self._on_search)
        row.addWidget(self._search)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedHeight(28)
        clear_btn.setFixedWidth(60)
        clear_btn.clicked.connect(self._clear_events)
        row.addWidget(clear_btn)

        export_btn = QPushButton("Export")
        export_btn.setFixedHeight(28)
        export_btn.setFixedWidth(65)
        export_btn.setToolTip("Export visible events to CSV")
        export_btn.clicked.connect(self._export_csv)
        row.addWidget(export_btn)

        return bar

    def _set_level_filter(self, level) -> None:
        self._filter_level = level
        self._btn_all.setChecked(level is None)
        self._btn_susp.setChecked(level == ThreatLevel.SUSPICIOUS)
        self._btn_dang.setChecked(level == ThreatLevel.DANGEROUS)
        self._apply_filter()

    def _on_search(self, text: str) -> None:
        self._filter_text = text.lower()
        self._apply_filter()

    def _apply_filter(self) -> None:
        for row in range(self._table.rowCount()):
            level_item = self._table.item(row, 1)
            msg_item   = self._table.item(row, 3)
            if not level_item:
                continue
            level_text = level_item.text().lower()
            msg_text   = (msg_item.text() if msg_item else "").lower()

            level_ok = (
                self._filter_level is None or
                self._state.t(f"threat_{self._filter_level.value}").lower() == level_text
            )
            text_ok = not self._filter_text or self._filter_text in msg_text

            self._table.setRowHidden(row, not (level_ok and text_ok))

    def _clear_events(self) -> None:
        self._table.setRowCount(0)
        self._all_events.clear()
        self._explain.clear()

    def _event_at(self, row: int) -> Event | None:
        for event, index in self._all_events:
            if index == row:
                return event
        return None

    def _on_select(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        event = self._event_at(rows[0].row()) if rows else None
        self._explain.setPlainText(
            explain(event, self._state.t) if event else "")

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Events", "maze_events.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Level", "Type", "Message"])
            for row in range(self._table.rowCount()):
                if self._table.isRowHidden(row):
                    continue
                writer.writerow([
                    (self._table.item(row, c) or QTableWidgetItem()).text()
                    for c in range(4)
                ])

    def add_event(self, event: Event) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        time_item  = QTableWidgetItem(event.timestamp.strftime("%H:%M:%S"))
        level_item = QTableWidgetItem(self._state.t(f"threat_{event.level.value}"))
        type_item  = QTableWidgetItem(event.type.value.replace("_", " ").title())
        msg_item   = QTableWidgetItem(event.message)

        color = QColor(THREAT_COLORS[event.level.value])
        level_item.setForeground(color)

        for col, item in enumerate((time_item, level_item, type_item, msg_item)):
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self._table.setItem(row, col, item)

        self._all_events.append((event, row))
        self._apply_filter()
        if not self._table.isRowHidden(row):
            self._table.scrollToBottom()

    def retranslate(self, _lang: str = None) -> None:
        self._table.setHorizontalHeaderLabels([
            self._state.t("col_time"),
            self._state.t("col_level"),
            self._state.t("col_type"),
            self._state.t("col_message"),
        ])

    def _show_context_menu(self, pos) -> None:
        if not self._engine:
            return
        row = self._table.rowAt(pos.y())
        if row < 0:
            return

        msg = (self._table.item(row, 3) or QTableWidgetItem()).text()
        ips   = _IP_RE.findall(msg)
        ports = [int(p) for p in _PORT_RE.findall(msg) if p.isdigit() and int(p) <= 65535]

        blockable_ips = [ip for ip in ips if not ip.startswith("127.")]
        if not blockable_ips and not ports:
            return

        menu = QMenu(self)
        for ip in blockable_ips:
            act = menu.addAction(f"Block IP  {ip}")
            act.setData(("ip", ip))

        if ports:
            menu.addSeparator()
            for port in ports:
                act_tcp = menu.addAction(f"Block Port  {port}/TCP")
                act_tcp.setData(("port_tcp", port))
                act_udp = menu.addAction(f"Block Port  {port}/UDP")
                act_udp.setData(("port_udp", port))

        chosen = menu.exec(self._table.viewport().mapToGlobal(pos))
        if not chosen:
            return

        kind, value = chosen.data()
        if kind == "ip":
            asyncio.ensure_future(self._engine.block_ip(value))
        elif kind == "port_tcp":
            asyncio.ensure_future(self._engine.block_port(value, "tcp"))
        elif kind == "port_udp":
            asyncio.ensure_future(self._engine.block_port(value, "udp"))
