import asyncio
import csv
import re
from collections import Counter

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QMenu, QPushButton, QLineEdit, QFileDialog, QSplitter, QTextEdit, QLabel,
)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt
from maze.core.events import Event, ThreatLevel
from maze.core.explain import explain
from maze.gui.theme import THREAT_COLORS
from maze.gui.widgets.common import attach_empty_state, setup_table

_IP_RE   = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_PORT_RE = re.compile(r'→\s*\S+:(\d{2,5})\b')
# Rows kept in the table. A long session on a noisy network otherwise grew the
# table (and memory) without bound; the oldest rows go first.
_MAX_ROWS = 3000
_EVENT_ROLE = Qt.ItemDataRole.UserRole


class EventListWidget(QWidget):
    def __init__(self, state, engine=None):
        super().__init__()
        self._state        = state
        self._engine       = engine
        self._filter_level = None   # None = all
        self._filter_text  = ""
        # Set by the main window: open the Threats dossier for a source IP.
        self.open_source = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 16, 24, 20)
        layout.setSpacing(12)
        layout.addLayout(self._build_filter_bar())

        self._table = QTableWidget(0, 4)
        setup_table(self._table, stretch=3, fit=(0, 1, 2))
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.itemSelectionChanged.connect(self._on_select)
        self._table.cellDoubleClicked.connect(lambda row, _c: self._open_row(row))
        self._empty = attach_empty_state(self._table, "")

        # A detection nobody can act on has done half a job. Selecting a row
        # says what the observation means and what to do about it.
        self._explain = QTextEdit()
        self._explain.setObjectName("detail")
        self._explain.setReadOnly(True)
        self._explain.setStyleSheet("font-family: sans-serif; font-size: 13px;")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(10)
        splitter.addWidget(self._table)
        splitter.addWidget(self._explain)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([560, 150])
        layout.addWidget(splitter, 1)

        state.language_changed.connect(self.retranslate)
        self.retranslate()

    def _build_filter_bar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)

        self._btn_all  = QPushButton()
        self._btn_susp = QPushButton()
        self._btn_dang = QPushButton()
        for btn in (self._btn_all, self._btn_susp, self._btn_dang):
            btn.setCheckable(True)
            row.addWidget(btn)
        self._btn_all.setChecked(True)
        self._btn_all.clicked.connect(lambda: self._set_level_filter(None))
        self._btn_susp.clicked.connect(lambda: self._set_level_filter(ThreatLevel.SUSPICIOUS))
        self._btn_dang.clicked.connect(lambda: self._set_level_filter(ThreatLevel.DANGEROUS))
        row.addSpacing(10)

        self._search = QLineEdit()
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_search)
        row.addWidget(self._search, 1)

        self._count = QLabel("")
        self._count.setObjectName("muted")
        row.addWidget(self._count)

        self._export_btn = QPushButton()
        self._export_btn.clicked.connect(self._export_csv)
        row.addWidget(self._export_btn)

        self._clear_btn = QPushButton()
        self._clear_btn.clicked.connect(self._clear_events)
        row.addWidget(self._clear_btn)
        return row

    # ── filtering ────────────────────────────────────────────────────────

    def _set_level_filter(self, level) -> None:
        self._filter_level = level
        self._btn_all.setChecked(level is None)
        self._btn_susp.setChecked(level == ThreatLevel.SUSPICIOUS)
        self._btn_dang.setChecked(level == ThreatLevel.DANGEROUS)
        self._apply_filter()

    def _on_search(self, text: str) -> None:
        self._filter_text = text.lower()
        self._apply_filter()

    def _matches(self, event: Event) -> bool:
        # Filter on the event, not on the cell text: the level column is
        # translated, and after a language switch the old rows no longer
        # matched the new word.
        if self._filter_level is not None and event.level != self._filter_level:
            return False
        if self._filter_text:
            hay = f"{event.message} {event.type.value}".lower()
            return self._filter_text in hay
        return True

    def _apply_filter(self) -> None:
        shown = 0
        for row in range(self._table.rowCount()):
            event = self._event_at(row)
            visible = event is not None and self._matches(event)
            self._table.setRowHidden(row, not visible)
            shown += visible
        self._update_count(shown)
        self._empty.sync()

    def _update_count(self, shown: int | None = None) -> None:
        total = self._table.rowCount()
        if shown is None:
            shown = sum(1 for r in range(total) if not self._table.isRowHidden(r))
        self._count.setText(
            self._state.t("ev_count").format(shown=shown, total=total))

    # ── data ─────────────────────────────────────────────────────────────

    def _event_at(self, row: int) -> Event | None:
        item = self._table.item(row, 0)
        return item.data(_EVENT_ROLE) if item else None

    def level_counts(self) -> Counter:
        """How many events of each level the list holds."""
        counts: Counter = Counter()
        for row in range(self._table.rowCount()):
            event = self._event_at(row)
            if event is not None:
                counts[event.level] += 1
        return counts

    def _clear_events(self) -> None:
        self._table.setRowCount(0)
        self._explain.clear()
        self._update_count()

    def _on_select(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        event = self._event_at(rows[0].row()) if rows else None
        self._explain.setPlainText(
            explain(event, self._state.t) if event else self._state.t("ev_select_hint"))

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, self._state.t("ev_export"), "maze_events.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Level", "Type", "Message"])
            for row in range(self._table.rowCount()):
                event = self._event_at(row)
                if event is None or self._table.isRowHidden(row):
                    continue
                writer.writerow([event.timestamp.isoformat(timespec="seconds"),
                                 event.level.value, event.type.value, event.message])

    def add_event(self, event: Event) -> None:
        if self._table.rowCount() >= _MAX_ROWS:
            self._table.removeRow(0)
        row = self._table.rowCount()
        self._table.insertRow(row)

        time_item  = QTableWidgetItem(event.timestamp.strftime("%H:%M:%S"))
        time_item.setData(_EVENT_ROLE, event)
        level_item = QTableWidgetItem(self._state.t(f"threat_{event.level.value}"))
        level_item.setForeground(QColor(THREAT_COLORS[event.level.value]))
        type_item  = QTableWidgetItem(self._type_name(event))
        msg_item   = QTableWidgetItem(event.message)
        msg_item.setToolTip(event.message)

        for col, item in enumerate((time_item, level_item, type_item, msg_item)):
            self._table.setItem(row, col, item)

        visible = self._matches(event)
        self._table.setRowHidden(row, not visible)
        self._update_count()
        self._empty.sync()
        if visible:
            self._table.scrollToBottom()

    def _type_name(self, event: Event) -> str:
        return self._state.t(f"evtype_{event.type.value}")

    @staticmethod
    def source_of(event: Event | None) -> str:
        """The address an event is about, if it names one."""
        if event is None:
            return ""
        data = event.data or {}
        return str(data.get("src") or data.get("ip") or "")

    def _open_row(self, row: int) -> None:
        ip = self.source_of(self._event_at(row))
        if ip and self.open_source:
            self.open_source(ip)

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._table.setHorizontalHeaderLabels([
            s.t("col_time"), s.t("col_level"), s.t("col_type"), s.t("col_message"),
        ])
        self._btn_all.setText(s.t("ev_all"))
        self._btn_susp.setText(s.t("threat_suspicious").title())
        self._btn_dang.setText(s.t("threat_dangerous").title())
        self._search.setPlaceholderText(s.t("ev_search"))
        self._export_btn.setText(s.t("ev_export"))
        self._export_btn.setToolTip(s.t("ev_export_tip"))
        self._clear_btn.setText(s.t("ev_clear"))
        self._empty.label.setText(s.t("ev_empty"))
        for row in range(self._table.rowCount()):
            event = self._event_at(row)
            item = self._table.item(row, 1)
            if event is not None and item is not None:
                item.setText(s.t(f"threat_{event.level.value}"))
                self._table.item(row, 2).setText(self._type_name(event))
        if not self._table.selectionModel().selectedRows():
            self._explain.setPlainText(s.t("ev_select_hint"))
        self._update_count()

    def _show_context_menu(self, pos) -> None:
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        s = self._state
        event = self._event_at(row)
        msg = event.message if event else ""
        ips   = _IP_RE.findall(msg)
        ports = [int(p) for p in _PORT_RE.findall(msg) if p.isdigit() and int(p) <= 65535]

        menu = QMenu(self)
        act_copy = menu.addAction(s.t("ev_copy"))
        source = self.source_of(event)
        act_open = None
        if source and self.open_source:
            act_open = menu.addAction(s.t("ev_open_threat"))
        blockable_ips = [ip for ip in dict.fromkeys(ips) if not ip.startswith("127.")]
        if blockable_ips or ports:
            menu.addSeparator()
        for ip in blockable_ips:
            menu.addAction(s.t("ev_block_ip").format(ip=ip)).setData(("ip", ip))
        for port in dict.fromkeys(ports):
            menu.addAction(s.t("dash_block_port").format(port=f"{port}/TCP")
                           ).setData(("port_tcp", port))
            menu.addAction(s.t("dash_block_port").format(port=f"{port}/UDP")
                           ).setData(("port_udp", port))

        chosen = menu.exec(self._table.viewport().mapToGlobal(pos))
        if not chosen:
            return
        if act_open is not None and chosen is act_open:
            self.open_source(source)
            return
        if chosen is act_copy:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(msg)
            return
        if not self._engine or not chosen.data():
            return
        kind, value = chosen.data()
        if kind == "ip":
            asyncio.ensure_future(self._engine.block_ip(value))
        elif kind == "port_tcp":
            asyncio.ensure_future(self._engine.block_port(value, "tcp"))
        elif kind == "port_udp":
            asyncio.ensure_future(self._engine.block_port(value, "udp"))
