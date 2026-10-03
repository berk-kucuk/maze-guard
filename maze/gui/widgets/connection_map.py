"""Connections page — which program is talking to whom, right now."""
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QHBoxLayout, QLabel, QLineEdit, QMenu,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from maze.gui.theme import THREAT_COLORS
from maze.gui.widgets.common import attach_empty_state, setup_table
from maze.protection.process_map import Connection

# Ports common enough that naming them is more useful than the number.
_SERVICES = {
    22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP", 853: "DNS-TLS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 3478: "STUN", 5222: "XMPP",
    5228: "Google Push", 8080: "HTTP-alt", 8443: "HTTPS-alt", 51820: "WireGuard",
}
_COLS = ("col_process", "col_pid", "col_remote", "conn_service", "col_local", "conn_status")


class ConnectionMapWidget(QWidget):
    def __init__(self, state, engine=None):
        super().__init__()
        self._state = state
        self._engine = engine
        self._conns: list[Connection] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 16, 24, 20)
        layout.setSpacing(12)

        bar = QHBoxLayout()
        bar.setSpacing(10)
        self._search = QLineEdit()
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(lambda _t: self._render())
        bar.addWidget(self._search, 1)
        self._only_unknown = QCheckBox()
        self._only_unknown.toggled.connect(lambda _c: self._render())
        bar.addWidget(self._only_unknown)
        self._count = QLabel("")
        self._count.setObjectName("muted")
        bar.addWidget(self._count)
        layout.addLayout(bar)

        self._table = QTableWidget(0, len(_COLS))
        setup_table(self._table, stretch=2, fit=(0, 1, 3, 4, 5))
        self._table.setSortingEnabled(False)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._menu)
        self._empty = attach_empty_state(self._table, "")
        layout.addWidget(self._table, 1)

        state.language_changed.connect(self.retranslate)
        self.retranslate()

    def _known(self, conn: Connection) -> bool | None:
        monitor = getattr(self._engine, "process_monitor", None)
        check = getattr(monitor, "_is_known", None)
        if check is None:
            return None
        try:
            return bool(check(conn))
        except Exception:
            return None

    def update_connections(self, conns: list[Connection]) -> None:
        self._conns = sorted(conns, key=lambda c: (c.process.lower(), c.remote_ip))
        self._render()

    def _render(self) -> None:
        s = self._state
        needle = self._search.text().strip().lower()
        only_unknown = self._only_unknown.isChecked()
        rows = []
        unknown_total = 0
        for c in self._conns:
            known = self._known(c)
            unknown_total += known is False
            if only_unknown and known is not False:
                continue
            service = _SERVICES.get(c.remote_port, "")
            hay = f"{c.process} {c.pid} {c.remote_addr} {service} {c.cmdline}".lower()
            if needle and needle not in hay:
                continue
            rows.append((c, known, service))

        self._table.setUpdatesEnabled(False)
        self._table.setRowCount(len(rows))
        for r, (c, known, service) in enumerate(rows):
            status = ("" if known is None else
                      s.t("conn_known") if known else s.t("conn_unknown"))
            values = (c.process, str(c.pid), c.remote_addr, service or "—",
                      c.local_addr, status)
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0 and c.cmdline:
                    item.setToolTip(c.cmdline)
                if col == 5 and known is False:
                    item.setForeground(QColor(THREAT_COLORS["suspicious"]))
                elif col == 5:
                    item.setForeground(QColor("#8b919a"))
                self._table.setItem(r, col, item)
        self._table.setUpdatesEnabled(True)
        self._count.setText(s.t("conn_count").format(
            shown=len(rows), total=len(self._conns), unknown=unknown_total))
        self._empty.sync()

    def _menu(self, pos) -> None:
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        s = self._state
        remote = (self._table.item(row, 2) or QTableWidgetItem()).text()
        ip = remote.rsplit(":", 1)[0].strip("[]")
        menu = QMenu(self)
        act_copy = menu.addAction(s.t("conn_copy_remote"))
        chosen = menu.exec(self._table.viewport().mapToGlobal(pos))
        if chosen is act_copy:
            QApplication.clipboard().setText(ip)

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._table.setHorizontalHeaderLabels([s.t(k) for k in _COLS])
        self._search.setPlaceholderText(s.t("conn_search"))
        self._only_unknown.setText(s.t("conn_only_unknown"))
        self._empty.label.setText(s.t("conn_empty"))
        self._render()
