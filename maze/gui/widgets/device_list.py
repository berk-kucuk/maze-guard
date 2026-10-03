"""
Devices tab — who is on this network, what they are, and whether they belong.

Three layers meet here:

  * the ARP watcher's live sighting of an address and a MAC,
  * the persistent inventory (maze.core.inventory) that remembers which
    devices belong on this network and what the user named them,
  * on-demand reconnaissance (maze.core.device_intel) at a chosen depth, whose
    results are cached only as long as they can still be true.

Anything a scan learns is folded back into the inventory, because that is the
layer keyed by MAC and therefore the only one that survives a DHCP lease.
"""
import asyncio
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QSplitter, QTextEdit, QMenu, QApplication, QLabel, QFrame,
    QFileDialog, QMessageBox, QLineEdit, QInputDialog, QPushButton,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor

from maze.gui.widgets.common import attach_empty_state, setup_table
from maze.core.device_intel import (
    DEFAULT_TTL, DeviceIntelCache, describe_progress, export_markdown,
    format_intel, summarize_intel,
)

_COLUMNS = ("col_ip", "col_mac", "dev_name", "dev_kind", "dev_known",
            "dev_info", "col_first_seen")
_COL_IP, _COL_MAC, _COL_NAME, _COL_KIND, _COL_KNOWN, _COL_INFO, _COL_SEEN = range(7)

# Scan depths offered in the context menu, shallowest first.
_PROFILES = (("quick", "dev_profile_quick"),
             ("standard", "dev_profile_standard"),
             ("thorough", "dev_profile_thorough"))

# Info-column colours by risk score.
_RISK_COLORS = ((60, "#ff3d00"), (30, "#ffab00"), (1, "#ffd54f"))
_UNKNOWN_COLOR = "#ffab00"
_KNOWN_COLOR = "#00e676"


class DeviceListWidget(QWidget):
    def __init__(self, state, engine=None, cfg=None):
        super().__init__()
        self._state = state
        self._engine = engine
        self._cfg = cfg
        self._devices: dict[str, dict] = {}
        self._rows: list[str] = []
        self._selected_ip: str | None = None
        self._filter = ""
        self._sort_col = _COL_IP
        self._sort_desc = False
        # IPs the user has just asked about. The cache only knows a scan is
        # running once its coroutine starts, which is a turn of the event loop
        # away — too late to make the right-click feel like it did something.
        self._pending: set[str] = set()

        self._inventory = getattr(engine, "inventory", None)
        self._ttl = float(getattr(cfg, "device_intel_ttl", DEFAULT_TTL) or DEFAULT_TTL)
        self._cache = DeviceIntelCache(
            interface=getattr(cfg, "interface", "") or "",
            ttl=self._ttl,
            incidents=getattr(engine, "incidents", None),
            inventory=self._inventory,
            identity=getattr(engine, "identity", None),
        )
        self._cache.start_watcher()

        self._build_ui()
        state.language_changed.connect(self.retranslate)

        # Drives the progress readout and keeps the "gathered Nm ago / expires
        # in Nm" line honest without waiting on the dashboard's device poll.
        self._tick = QTimer(self)
        self._tick.setInterval(700)
        self._tick.timeout.connect(self._on_tick)
        self._tick.start()

        self.retranslate()

    def _on_tick(self) -> None:
        # Redrawing every row 1.4x a second for a hidden tab is wasted work;
        # showEvent redraws once when it comes back.
        if self.isVisible():
            self._refresh_view()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh_view()

    # ── build ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 16, 24, 20)
        layout.setSpacing(12)
        layout.addLayout(self._build_toolbar())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(12)
        splitter.addWidget(self._build_table())
        splitter.addWidget(self._build_detail())
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([780, 320])
        layout.addWidget(splitter, 1)

    def _build_toolbar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        self._search = QLineEdit()
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_filter)
        row.addWidget(self._search, 1)

        self._summary = QLabel("")
        self._summary.setObjectName("muted")
        row.addWidget(self._summary)

        # The actions used to live only in a right-click menu nobody finds.
        self._btn_scan = QPushButton()
        self._btn_scan.setObjectName("primary")
        self._btn_scan.clicked.connect(
            lambda: self._gather("standard", force=self._selected_has_intel()))
        self._btn_trust = QPushButton()
        self._btn_trust.clicked.connect(self._toggle_trust_selected)
        self._btn_label = QPushButton()
        self._btn_label.clicked.connect(self._label_selected)
        self._btn_scan_all = QPushButton()
        self._btn_scan_all.clicked.connect(lambda: self._gather_all("quick"))
        for b in (self._btn_scan, self._btn_trust, self._btn_label, self._btn_scan_all):
            row.addWidget(b)
        return row

    def _selected_has_intel(self) -> bool:
        ip = self._selected_ip
        if not ip:
            return False
        return self._cache.get(ip, self._devices.get(ip, {}).get("mac", "")) is not None

    def _toggle_trust_selected(self) -> None:
        ip = self._selected_ip
        rec = self._record(ip) if ip else None
        if rec is None or self._inventory is None:
            return
        mac = self._devices.get(ip, {}).get("mac", "")
        self._inventory.set_trusted(mac, self._cache.network_id, not rec.trusted)
        self._refresh_view()

    def _label_selected(self) -> None:
        ip = self._selected_ip
        if not ip:
            return
        mac = self._devices.get(ip, {}).get("mac", "")
        self._edit_label(ip, mac, self._record(ip))

    def _update_buttons(self) -> None:
        s = self._state
        ip = self._selected_ip
        rec = self._record(ip) if ip else None
        scanning = bool(ip) and self._is_scanning(ip)
        self._btn_scan.setEnabled(bool(ip) and not scanning)
        self._btn_scan.setText(s.t("dev_btn_rescan") if self._selected_has_intel()
                               else s.t("dev_btn_scan"))
        self._btn_trust.setEnabled(rec is not None)
        self._btn_trust.setText(s.t("dev_mark_unknown") if (rec and rec.trusted)
                                else s.t("dev_mark_known"))
        self._btn_label.setEnabled(rec is not None)
        self._btn_scan_all.setEnabled(bool(self._devices))

    def _build_table(self) -> QTableWidget:
        self._table = QTableWidget(0, len(_COLUMNS))
        setup_table(self._table, stretch=_COL_INFO,
                    fit=(_COL_IP, _COL_MAC, _COL_NAME, _COL_KIND, _COL_KNOWN,
                         _COL_SEEN))
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._empty = attach_empty_state(self._table, "")

        header = self._table.horizontalHeader()
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._on_sort)

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_menu)
        self._table.itemSelectionChanged.connect(self._on_select)
        self._table.doubleClicked.connect(lambda *_: self._gather("standard"))
        return self._table

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
        self._detail.setStyleSheet("QTextEdit { border: none; background: transparent; }")
        layout.addWidget(self._detail)
        return frame

    # ── data ─────────────────────────────────────────────────────────────

    def update_devices(self, devices: dict[str, dict]) -> None:
        # The widget is built before the event loop runs, so the shared
        # identity poll cannot start in __init__. Retrying here — the call is
        # idempotent — is what actually gets it running.
        self._cache.start_watcher()
        self._cache.set_interface(getattr(self._cfg, "interface", "") or "")
        self._devices = dict(devices)
        self._refresh_view()

    def _record(self, ip: str):
        """The inventory entry behind an address, if we have one."""
        if self._inventory is None:
            return None
        mac = self._devices.get(ip, {}).get("mac", "")
        if not mac:
            return None
        return self._inventory.get(mac, self._cache.network_id)

    def _visible_ips(self) -> list[str]:
        ips = list(self._devices)
        if self._filter:
            ips = [ip for ip in ips if self._matches(ip)]
        return sorted(ips, key=self._sort_key, reverse=self._sort_desc)

    def _matches(self, ip: str) -> bool:
        rec = self._record(ip)
        intel = self._cache.get(ip)
        haystack = " ".join(filter(None, [
            ip,
            self._devices.get(ip, {}).get("mac", ""),
            rec.display_name if rec else "",
            rec.kind if rec else "",
            intel.name if intel else "",
            intel.device_kind if intel else "",
            intel.vendor if intel else "",
        ])).lower()
        return self._filter in haystack

    def _sort_key(self, ip: str):
        rec = self._record(ip)
        intel = self._cache.get(ip)
        if self._sort_col == _COL_IP:
            return _ip_key(ip)
        if self._sort_col == _COL_MAC:
            return self._devices.get(ip, {}).get("mac", "")
        if self._sort_col == _COL_NAME:
            return (rec.display_name if rec else (intel.name if intel else "")).lower()
        if self._sort_col == _COL_KIND:
            return (rec.kind if rec else (intel.device_kind if intel else "")).lower()
        if self._sort_col == _COL_KNOWN:
            return 0 if (rec and rec.trusted) else 1
        if self._sort_col == _COL_INFO:
            return -(intel.risk_score if intel else -1)
        first = self._devices.get(ip, {}).get("first_seen")
        return first or datetime.now()

    def _on_filter(self, text: str) -> None:
        self._filter = text.strip().lower()
        self._refresh_view()

    def _on_sort(self, col: int) -> None:
        self._sort_desc = not self._sort_desc if col == self._sort_col else False
        self._sort_col = col
        self._refresh_view()

    def _refresh_view(self) -> None:
        ips = self._visible_ips()
        if ips != self._rows:
            self._rebuild(ips)
        else:
            for row, ip in enumerate(ips):
                self._fill_row(row, ip)
        self._update_summary()
        self._update_buttons()
        self._empty.sync()
        self._show_detail(self._selected_ip)

    def _update_summary(self) -> None:
        s = self._state
        total = len(self._devices)
        unknown = sum(1 for ip in self._devices
                      if (r := self._record(ip)) is not None and not r.trusted)
        parts = [f"{total} {s.t('dev_count')}"]
        if unknown:
            parts.append(f"{unknown} {s.t('dev_unknown_count')}")
        if self._inventory is not None and self._inventory.is_learning(
                self._cache.network_id):
            parts.append(s.t("dev_learning"))
        self._summary.setText("  ·  ".join(parts))

    def _rebuild(self, ips: list[str]) -> None:
        self._table.setUpdatesEnabled(False)
        self._table.blockSignals(True)
        self._table.setRowCount(len(ips))
        for row, ip in enumerate(ips):
            self._fill_row(row, ip)
        self._rows = ips
        if self._selected_ip in ips:
            self._table.selectRow(ips.index(self._selected_ip))
        self._table.blockSignals(False)
        self._table.setUpdatesEnabled(True)

    def _fill_row(self, row: int, ip: str) -> None:
        s = self._state
        info = self._devices.get(ip, {})
        mac = info.get("mac", "")
        intel = self._cache.get(ip, mac)
        rec = self._record(ip)

        ts = info.get("first_seen") or datetime.now()
        if self._is_scanning(ip):
            status = describe_progress(self._cache.progress(ip), s.t)
            color = "#888888"
        elif intel is None:
            status, color = "—", ""
        else:
            status = summarize_intel(intel, s.t)
            color = _risk_color(intel.risk_score) if not intel.error else "#ff3d00"

        if rec is None:
            known, known_color = "", ""
        elif rec.trusted:
            known, known_color = s.t("dev_known_yes"), _KNOWN_COLOR
        else:
            known, known_color = s.t("dev_known_no"), _UNKNOWN_COLOR

        name = (rec.display_name if rec and (rec.label or rec.name)
                else (intel.name if intel else "")) or ""
        kind = (intel.device_kind if intel else "") or (rec.kind if rec else "")

        for col, text in enumerate((ip, mac, name, kind, known, status,
                                    ts.strftime("%H:%M:%S"))):
            item = self._table.item(row, col)
            if item is None:
                item = QTableWidgetItem()
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self._table.setItem(row, col, item)
            if item.text() != text:
                item.setText(text)

        vendor = (intel.vendor if intel else "") or (rec.vendor if rec else "")
        self._table.item(row, _COL_MAC).setToolTip(vendor)
        self._paint(row, _COL_INFO, color)
        self._paint(row, _COL_KNOWN, known_color)

    def _paint(self, row: int, col: int, color: str) -> None:
        item = self._table.item(row, col)
        if item is not None:
            item.setForeground(QColor(color) if color
                               else self._table.palette().text())

    def _row_ip(self, row: int) -> str | None:
        item = self._table.item(row, _COL_IP)
        return item.text() if item else None

    def _on_select(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        self._selected_ip = self._row_ip(rows[0].row()) if rows else None
        self._update_buttons()
        self._show_detail(self._selected_ip)

    def _show_detail(self, ip: str | None) -> None:
        s = self._state
        if ip is None:
            text = s.t("dev_hint")
        elif self._is_scanning(ip):
            text = (f"{ip}\n\n{describe_progress(self._cache.progress(ip), s.t)}"
                    f"\n\n{s.t('dev_scan_running')}")
        else:
            text = self._detail_text(ip)
        if text != self._detail.toPlainText():
            bar = self._detail.verticalScrollBar()
            offset = bar.value()
            self._detail.setPlainText(text)
            bar.setValue(min(offset, bar.maximum()))

    def _detail_text(self, ip: str) -> str:
        s = self._state
        mac = self._devices.get(ip, {}).get("mac", "")
        intel = self._cache.get(ip, mac)
        header = self._history_block(ip)
        if intel is None:
            return f"{ip}\n{header}\n{s.t('dev_hint')}" if header else \
                   f"{ip}\n\n{s.t('dev_hint')}"
        return (header + "\n" if header else "") + format_intel(intel, s.t, self._ttl)

    def _history_block(self, ip: str) -> str:
        """What the inventory remembers about this device, above the scan."""
        rec = self._record(ip)
        if rec is None:
            return ""
        s = self._state
        lines = [f"── {s.t('dev_history')} ──"]
        if rec.label:
            lines.append(f"{s.t('dev_label')}: {rec.label}")
        lines.append(f"{s.t('dev_known')}: "
                     + (s.t("dev_known_yes") if rec.trusted else s.t("dev_known_no")))
        lines.append(f"{s.t('dev_first_on_network')}: "
                     f"{rec.first_seen:%Y-%m-%d %H:%M}")
        lines.append(f"{s.t('dev_times_seen')}: {rec.times_seen}")
        if len(rec.ips) > 1:
            lines.append(f"{s.t('dev_past_ips')}: {', '.join(rec.ips[1:6])}")
        if rec.randomized_mac:
            lines.append(f"! {s.t('dev_random_mac_note')}")
        return "\n".join(lines) + "\n"

    # ── context menu ─────────────────────────────────────────────────────

    def _show_menu(self, pos) -> None:
        s = self._state
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        self._table.selectRow(row)
        ip = self._row_ip(row)
        if not ip:
            return
        mac = self._devices.get(ip, {}).get("mac", "")
        intel = self._cache.get(ip, mac)
        rec = self._record(ip)
        scanning = self._is_scanning(ip)

        menu = QMenu(self)
        scan_menu = menu.addMenu(s.t("dev_rescan") if intel else s.t("dev_scan"))
        scan_menu.setEnabled(not scanning)
        scan_actions = {}
        for profile, key in _PROFILES:
            act = scan_menu.addAction(s.t(key))
            act.setToolTip(s.t(f"dev_profile_{profile}_hint"))
            scan_actions[act] = profile

        all_menu = menu.addMenu(s.t("dev_scan_all"))
        all_actions = {}
        for profile, key in _PROFILES:
            all_actions[all_menu.addAction(s.t(key))] = profile

        menu.addSeparator()
        act_label = menu.addAction(s.t("dev_set_label"))
        act_label.setEnabled(rec is not None)
        act_trust = menu.addAction(
            s.t("dev_mark_unknown") if (rec and rec.trusted) else s.t("dev_mark_known"))
        act_trust.setEnabled(rec is not None)

        menu.addSeparator()
        act_forget = menu.addAction(s.t("dev_forget"))
        act_forget.setEnabled(intel is not None)
        act_export = menu.addAction(s.t("dev_export"))
        act_export.setEnabled(intel is not None and not intel.error)
        menu.addSeparator()
        act_copy_ip = menu.addAction(s.t("dev_copy_ip"))
        act_copy_mac = menu.addAction(s.t("dev_copy_mac"))
        act_copy_mac.setEnabled(bool(mac))
        act_copy_report = menu.addAction(s.t("dev_copy_report"))
        act_copy_report.setEnabled(intel is not None)
        menu.addSeparator()
        act_clear = menu.addAction(s.t("dev_clear_all"))

        chosen = menu.exec(self._table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen in scan_actions:
            self._gather(scan_actions[chosen], force=intel is not None)
        elif chosen in all_actions:
            self._gather_all(all_actions[chosen])
        elif chosen is act_label:
            self._edit_label(ip, mac, rec)
        elif chosen is act_trust and rec is not None:
            self._inventory.set_trusted(mac, self._cache.network_id,
                                        not rec.trusted)
            self._refresh_view()
        elif chosen is act_forget:
            self._cache.forget(ip)
            self._refresh_view()
        elif chosen is act_export and intel is not None:
            self._export(intel)
        elif chosen is act_copy_ip:
            _copy(ip)
        elif chosen is act_copy_mac:
            _copy(mac)
        elif chosen is act_copy_report and intel is not None:
            _copy(self._detail_text(ip))
        elif chosen is act_clear:
            self._cache.clear()
            self._refresh_view()

    def _edit_label(self, ip: str, mac: str, rec) -> None:
        if rec is None or self._inventory is None:
            return
        s = self._state
        text, ok = QInputDialog.getText(
            self, s.t("dev_set_label"), f"{ip}  ({mac})",
            QLineEdit.EchoMode.Normal, rec.label)
        if ok:
            self._inventory.set_label(mac, self._cache.network_id, text)
            self._refresh_view()

    # ── actions ──────────────────────────────────────────────────────────

    def _is_scanning(self, ip: str) -> bool:
        return ip in self._pending or self._cache.is_scanning(ip)

    def _gather(self, profile: str = "standard", force: bool = False) -> None:
        ip = self._selected_ip
        if ip:
            self._start(ip, profile, force)
        self._refresh_view()

    def _gather_all(self, profile: str = "standard") -> None:
        """Sweep every device on screen. The cache's own semaphore paces this,
        so a 30-device network does not become 30 simultaneous scans."""
        for ip in self._visible_ips():
            self._start(ip, profile, force=False)
        self._refresh_view()

    def _start(self, ip: str, profile: str, force: bool) -> None:
        if self._is_scanning(ip):
            return
        mac = self._devices.get(ip, {}).get("mac", "")
        self._pending.add(ip)
        asyncio.ensure_future(self._async_gather(ip, mac, profile, force))

    async def _async_gather(self, ip: str, mac: str, profile: str,
                            force: bool) -> None:
        try:
            await self._cache.gather(ip, mac, force=force, profile=profile)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            self._pending.discard(ip)
        self._refresh_view()

    def _export(self, intel) -> None:
        default = f"maze-device-{intel.ip.replace('.', '-')}.md"
        path, _ = QFileDialog.getSaveFileName(
            self, self._state.t("dev_export"), default,
            "Markdown (*.md);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(export_markdown(intel))
        except OSError as exc:
            QMessageBox.warning(self, "Maze Guard",
                                f"{self._state.t('dev_export_failed')}\n\n{exc}")

    # ── i18n ─────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        s = self._state
        self._table.setHorizontalHeaderLabels([s.t(k) for k in _COLUMNS])
        self._detail_title.setText(s.t("dev_detail_title"))
        self._search.setPlaceholderText(s.t("dev_search"))
        self._btn_label.setText(s.t("dev_set_label"))
        self._btn_scan_all.setText(s.t("dev_btn_scan_all"))
        self._btn_scan_all.setToolTip(s.t("dev_profile_quick_hint"))
        self._empty.label.setText(s.t("dev_empty"))
        self._refresh_view()


def _ip_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _risk_color(score: int) -> str:
    for threshold, color in _RISK_COLORS:
        if score >= threshold:
            return color
    return _KNOWN_COLOR


def _copy(text: str) -> None:
    clip = QApplication.clipboard()
    if clip and text:
        clip.setText(text)
