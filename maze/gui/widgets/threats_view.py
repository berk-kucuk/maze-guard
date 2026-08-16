"""
Threats tab — the dossier on every source that has attacked this host.

The event list answers "what happened". This answers "who did it, and what do
we know about them", which is the view you actually want open when something
is going on.
"""
import asyncio
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QLabel, QPushButton, QTextEdit,
    QFrame, QFileDialog, QMessageBox,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor

SEVERITY_COLORS = {
    "critical": "#ff1744",
    "high":     "#ff3d00",
    "medium":   "#ffab00",
    "low":      "#ffd54f",
    "info":     "#888888",
}


def _fmt_ago(when: datetime) -> str:
    secs = max(0, int((datetime.now() - when).total_seconds()))
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


class ThreatsView(QWidget):
    def __init__(self, state, engine):
        super().__init__()
        self._state = state
        self._engine = engine
        self._selected_ip: str | None = None
        self._busy = False

        self._build_ui()
        state.language_changed.connect(self.retranslate)

        self._timer = QTimer(self)
        self._timer.setInterval(4000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        QTimer.singleShot(200, self.refresh)

    # ── build ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        root.addLayout(self._build_toolbar())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.addWidget(self._build_table())
        splitter.addWidget(self._build_detail())
        splitter.setSizes([520, 520])
        root.addWidget(splitter)

        self.retranslate()

    def _build_toolbar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        self._summary = QLabel("")
        self._summary.setStyleSheet("font-size: 12px; color: #888;")
        row.addWidget(self._summary)
        row.addStretch()

        self._block_btn = QPushButton()
        self._block_btn.setFixedHeight(28)
        self._block_btn.clicked.connect(self._toggle_block)
        row.addWidget(self._block_btn)

        self._scan_btn = QPushButton()
        self._scan_btn.setFixedHeight(28)
        self._scan_btn.clicked.connect(self._rescan)
        row.addWidget(self._scan_btn)

        self._export_btn = QPushButton()
        self._export_btn.setFixedHeight(28)
        self._export_btn.clicked.connect(self._export)
        row.addWidget(self._export_btn)

        self._clear_btn = QPushButton()
        self._clear_btn.setFixedHeight(28)
        self._clear_btn.clicked.connect(self._clear)
        row.addWidget(self._clear_btn)

        for btn in (self._block_btn, self._scan_btn, self._export_btn):
            btn.setEnabled(False)
        return row

    def _build_table(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 12)
        layout.setSpacing(8)

        self._table_title = QLabel()
        self._table_title.setObjectName("card_title")
        layout.addWidget(self._table_title)

        self._table = QTableWidget(0, 5)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        for col, width in ((1, 90), (2, 60), (3, 90), (4, 80)):
            self._table.setColumnWidth(col, width)
            self._table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.Fixed)
        self._table.itemSelectionChanged.connect(self._on_select)
        layout.addWidget(self._table)
        return frame

    def _build_detail(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 12)
        layout.setSpacing(8)

        self._detail_title = QLabel()
        self._detail_title.setObjectName("card_title")
        layout.addWidget(self._detail_title)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setStyleSheet("font-family: monospace; font-size: 12px;")
        layout.addWidget(self._detail)
        return frame

    # ── data ──────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        s = self._state
        attackers = self._engine.incidents.all()

        active = self._engine.incidents.active(60)
        blocked = sum(1 for a in attackers if a.blocked)
        self._summary.setText(
            f"{len(attackers)} {s.t('threats_tracked')}  ·  "
            f"{len(active)} {s.t('threats_recent')}  ·  "
            f"{blocked} {s.t('threats_blocked')}"
        )

        self._table.setRowCount(0)
        for att in attackers:
            row = self._table.rowCount()
            self._table.insertRow(row)
            label = att.ip
            if att.hostname:
                label += f"  ({att.hostname})"
            self._table.setItem(row, 0, QTableWidgetItem(label))

            sev = QTableWidgetItem(s.t(f"sev_{att.severity}"))
            sev.setForeground(QColor(SEVERITY_COLORS.get(att.severity, "#888")))
            self._table.setItem(row, 1, sev)

            self._table.setItem(row, 2, QTableWidgetItem(str(int(att.score()))))
            self._table.setItem(row, 3, QTableWidgetItem(_fmt_ago(att.last_seen)))

            status = QTableWidgetItem(
                s.t("threats_is_blocked") if att.blocked else "—")
            if att.blocked:
                status.setForeground(QColor("#00e676"))
            self._table.setItem(row, 4, status)

            if att.ip == self._selected_ip:
                self._table.selectRow(row)

        if not attackers:
            self._detail.setPlainText(s.t("threats_empty"))
            self._selected_ip = None
            self._update_buttons(None)
        elif self._selected_ip:
            self._show_detail(self._selected_ip)

    def _on_select(self) -> None:
        items = self._table.selectedItems()
        if not items:
            return
        ip = self._table.item(items[0].row(), 0).text().split(" ")[0]
        self._selected_ip = ip
        self._show_detail(ip)

    def _show_detail(self, ip: str) -> None:
        att = self._engine.incidents.get(ip)
        if att is None:
            self._detail.clear()
            self._update_buttons(None)
            return
        self._update_buttons(att)

        s = self._state
        lines = [
            f"{s.t('threats_severity')}: {s.t('sev_' + att.severity).upper()}"
            f"   ({int(att.score())}/100)",
            f"{s.t('threats_first_seen')}: {att.first_seen:%Y-%m-%d %H:%M:%S}",
            f"{s.t('threats_last_seen')}:  {att.last_seen:%Y-%m-%d %H:%M:%S}"
            f"  ({_fmt_ago(att.last_seen)})",
            "",
            f"── {s.t('threats_identity')} ──",
            f"IP:        {att.ip}",
            f"MAC:       {att.mac or '—'}"
            + (f"  ({att.vendor})" if att.vendor else ""),
            f"Hostname:  {att.hostname or '—'}",
            f"OS:        {att.os_hint or '—'}",
            "",
            f"── {s.t('threats_activity')} ──",
            f"{s.t('threats_techniques')}: "
            f"{', '.join(sorted(att.techniques)) or '—'}",
            f"{s.t('threats_packets')}: {att.packets}",
        ]
        if att.ports_targeted:
            ports = sorted(att.ports_targeted)
            shown = ", ".join(str(p) for p in ports[:30])
            more = f"  (+{len(ports) - 30})" if len(ports) > 30 else ""
            lines.append(f"{s.t('threats_ports')} ({len(ports)}): {shown}{more}")

        recon = att.recon or {}
        if recon:
            lines += ["", f"── {s.t('threats_recon')} ──"]
            if recon.get("latency_ms"):
                lines.append(f"RTT:       {recon['latency_ms']} ms")
            if recon.get("randomized_mac"):
                lines.append(s.t("threats_random_mac"))
            open_ports = recon.get("open_ports") or att.open_ports
            if open_ports:
                lines.append(f"{s.t('threats_open_ports')}:")
                for entry in open_ports:
                    port, name = (entry if isinstance(entry, (list, tuple))
                                  else (entry, "?"))
                    banner = (att.banners.get(str(port))
                              or (recon.get("http_titles") or {}).get(str(port), ""))
                    lines.append(f"  {port:>6}/{name}"
                                 + (f"   {banner}" if banner else ""))
            for port, info in (recon.get("tls_info") or {}).items():
                cn = info.get("subject_cn") or info.get("subject") or "?"
                lines.append(f"TLS {port}:   CN={cn}"
                             + ("  [self-signed]" if info.get("self_signed") else "")
                             + (f"  {info.get('tls_version', '')}"))
            if recon.get("findings"):
                lines.append("")
                lines.append(f"{s.t('threats_findings')}:")
                for f in recon["findings"]:
                    lines.append(f"  ! {f}")

        if att.actions:
            lines += ["", f"── {s.t('threats_actions')} ──"]
            for act in att.actions[-10:]:
                lines.append(f"  {act.get('ts', '')}  {act.get('what', '')}")

        lines += ["", f"── {s.t('threats_timeline')} ──"]
        for ev in list(att.evidence)[-40:]:
            lines.append(f"  {ev.ts:%H:%M:%S}  [{ev.level}] {ev.message}")

        text = "\n".join(lines)
        if text == self._detail.toPlainText():
            return          # nothing changed — don't yank the scroll position
        bar = self._detail.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        offset = bar.value()
        self._detail.setPlainText(text)
        bar.setValue(bar.maximum() if at_bottom else min(offset, bar.maximum()))

    def _update_buttons(self, att) -> None:
        s = self._state
        has = att is not None
        for btn in (self._block_btn, self._scan_btn, self._export_btn):
            btn.setEnabled(has and not self._busy)
        self._block_btn.setText(
            s.t("threats_unblock") if (has and att.blocked) else s.t("threats_block"))

    # ── actions ───────────────────────────────────────────────────────────

    def _toggle_block(self) -> None:
        if not self._selected_ip:
            return
        att = self._engine.incidents.get(self._selected_ip)
        if att is None:
            return
        asyncio.ensure_future(self._async_block(self._selected_ip, att.blocked))

    async def _async_block(self, ip: str, currently_blocked: bool) -> None:
        self._busy = True
        try:
            ok = (await self._engine.unblock_ip(ip) if currently_blocked
                  else await self._engine.block_ip(ip))
        finally:
            self._busy = False
        if not ok:
            self._warn(self._state.t("threats_block_failed")
                       + f"\n\n{self._engine.firewall_error()}")
        self.refresh()

    def _rescan(self) -> None:
        if self._selected_ip:
            asyncio.ensure_future(self._async_rescan(self._selected_ip))

    async def _async_rescan(self, ip: str) -> None:
        self._busy = True
        self._scan_btn.setEnabled(False)
        self._detail.append("\n" + self._state.t("threats_scanning"))
        try:
            await self._engine.rescan(ip)
        finally:
            self._busy = False
        self.refresh()

    def _export(self) -> None:
        if not self._selected_ip:
            return
        att = self._engine.incidents.get(self._selected_ip)
        if att is None:
            return
        default = f"maze-incident-{self._selected_ip.replace('.', '-')}.md"
        path, _ = QFileDialog.getSaveFileName(
            self, self._state.t("threats_export"), default,
            "Markdown (*.md);;All files (*)")
        if not path:
            return
        if self._engine.incidents.export_report(self._selected_ip, path):
            self._summary.setText(f"{self._state.t('threats_exported')}: {path}")
        else:
            self._warn(self._state.t("threats_export_failed"))

    def _clear(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(self._state.t("threats_clear"))
        box.setText(self._state.t("threats_clear_confirm"))
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self._engine.incidents.clear()
        self._selected_ip = None
        self._detail.clear()
        self.refresh()

    def _warn(self, text: str) -> None:
        QMessageBox.warning(self, "Maze Guard", text)

    # ── i18n ──────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._table_title.setText(s.t("threats_title"))
        self._detail_title.setText(s.t("threats_detail"))
        self._table.setHorizontalHeaderLabels([
            s.t("threats_source"), s.t("threats_severity"),
            s.t("threats_score"), s.t("threats_last_seen"),
            s.t("col_status"),
        ])
        self._scan_btn.setText(s.t("threats_rescan"))
        self._export_btn.setText(s.t("threats_export"))
        self._clear_btn.setText(s.t("threats_clear"))
        self._block_btn.setText(s.t("threats_block"))
        self.refresh()
