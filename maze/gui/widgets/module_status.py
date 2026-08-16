import asyncio
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QScrollArea, QFrame, QHBoxLayout,
    QLabel, QPushButton, QMessageBox,
)
from PyQt6.QtCore import Qt


# (engine_key, i18n_key, category_i18n_key)
#
# "fw_backend" and "firewall" are not engine modules: the first drives the
# firewalld unit itself, the second the zone's inbound-DROP shield. They are
# listed here because that is where a user looks for them.
MODULES = [
    ("arp_watch",       "module_arp_watch",       "cat_detection"),
    ("rogue_ap",        "module_rogue_ap",         "cat_detection"),
    ("dns_validate",    "module_dns_validate",     "cat_detection"),
    ("tls",             "module_tls",              "cat_detection"),
    ("ssl_strip",       "module_ssl_strip",        "cat_detection"),
    ("anomaly",         "module_anomaly",          "cat_detection"),
    ("hostname",        "module_hostname",         "cat_stealth"),
    ("service_blocker", "module_service_blocker",  "cat_stealth"),
    ("fingerprint",     "module_fingerprint",      "cat_stealth"),
    ("fw_backend",      "module_fw_backend",       "cat_protection"),
    ("firewall",        "module_firewall",         "cat_protection"),
    ("port_scan",       "module_port_scan",        "cat_protection"),
    ("process",         "module_process",          "cat_protection"),
    ("dns_leak",        "module_dns_leak",         "cat_protection"),
]


def _polish(btn: QPushButton) -> None:
    btn.style().unpolish(btn)
    btn.style().polish(btn)
    btn.update()


class _Row:
    """One module line: name, sub-caption, status word and toggle."""

    def __init__(self, name_lbl: QLabel, detail_lbl: QLabel,
                 status_lbl: QLabel, btn: QPushButton):
        self.name = name_lbl
        self.detail = detail_lbl
        self.status = status_lbl
        self.btn = btn


class ModuleStatusWidget(QWidget):
    def __init__(self, state, engine):
        super().__init__()
        self._state = state
        self._engine = engine
        self._rows: dict[str, _Row] = {}
        self._fw_state = None
        self._busy: set[str] = set()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        self._inner = QVBoxLayout(container)
        self._inner.setContentsMargins(24, 16, 24, 16)
        self._inner.setSpacing(0)

        scroll.setWidget(container)
        layout.addWidget(scroll)

        self._msg = QLabel("")
        self._msg.setWordWrap(True)
        self._msg.setStyleSheet("font-size: 12px; color: #888; padding: 6px 24px;")
        layout.addWidget(self._msg)

        self._build_rows()
        state.language_changed.connect(self.retranslate)
        self.refresh()

    # ── build ─────────────────────────────────────────────────────────────

    def _build_rows(self) -> None:
        current_cat = None

        for key, i18n_key, cat_key in MODULES:
            if cat_key != current_cat:
                current_cat = cat_key
                self._add_category_header(cat_key)

            name_lbl = QLabel(self._state.t(i18n_key))
            name_lbl.setStyleSheet("font-size: 13px;")

            detail_lbl = QLabel("")
            detail_lbl.setStyleSheet("font-size: 11px; color: #777;")

            status_lbl = QLabel("")
            status_lbl.setFixedWidth(90)
            status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            btn = QPushButton("○")
            btn.setFixedWidth(44)
            btn.setFixedHeight(30)
            btn.setProperty("active", False)
            btn.clicked.connect(lambda _, k=key: self._toggle(k))
            _polish(btn)

            if key == "fw_backend":
                btn.setToolTip(self._state.t("tip_fw_backend"))
            elif key == "firewall":
                btn.setToolTip(self._state.t("tip_fw_shield"))

            self._rows[key] = _Row(name_lbl, detail_lbl, status_lbl, btn)

            text_col = QVBoxLayout()
            text_col.setContentsMargins(0, 0, 0, 0)
            text_col.setSpacing(1)
            text_col.addWidget(name_lbl)
            text_col.addWidget(detail_lbl)

            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 6, 0, 6)
            row_layout.setSpacing(12)
            row_layout.addLayout(text_col)
            row_layout.addStretch()
            row_layout.addWidget(status_lbl)
            row_layout.addWidget(btn)

            self._inner.addWidget(row_widget)

            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setFixedHeight(1)
            self._inner.addWidget(sep)

        self._inner.addStretch()

    def _add_category_header(self, cat_key: str) -> None:
        lbl = QLabel(self._state.t(cat_key).upper())
        lbl.setStyleSheet(
            "font-size: 10px; font-weight: bold; letter-spacing: 2px; "
            "color: #555555; padding-top: 16px; padding-bottom: 6px;"
        )
        self._inner.addWidget(lbl)

    # ── toggling ──────────────────────────────────────────────────────────

    def _toggle(self, key: str) -> None:
        if key in self._busy:
            return
        if key == "fw_backend":
            asyncio.ensure_future(self._toggle_fw_backend())
        elif key == "firewall":
            asyncio.ensure_future(self._toggle_shield())
        else:
            asyncio.ensure_future(self._toggle_module(key))

    async def _toggle_module(self, key: str) -> None:
        self._busy.add(key)
        try:
            await self._engine.toggle_module(key)
        finally:
            self._busy.discard(key)
        self.refresh()

    async def _toggle_fw_backend(self) -> None:
        # max_age=0: never decide whether to stop the firewall, or what to warn
        # the user about, from a cached reading.
        state = await self._engine.firewall_state(max_age=0)
        if not state.installed:
            self._show_error(self._state.t("fw_msg_missing"))
            return
        if state.running:
            # Turning the firewall off leaves the host exposed — never do it on
            # a single mis-click; make the consequence explicit first.
            if not self._confirm(self._state.t("fw_confirm_title"),
                                 self._state.t("fw_confirm_body")):
                return
        self._busy.add("fw_backend")
        self._set_pending("fw_backend")
        try:
            ok = await self._engine.set_firewall_enabled(not state.running)
        finally:
            self._busy.discard("fw_backend")
        if ok:
            self._show_info(self._state.t(
                "fw_msg_stopped" if state.running else "fw_msg_started"))
        else:
            self._show_error(self._engine.firewall_error()
                             or self._state.t("fw_msg_failed"))
        self.refresh()

    async def _toggle_shield(self) -> None:
        state = await self._engine.firewall_state(max_age=0)
        if not state.running:
            self._show_error(self._state.t("fw_msg_need_running"))
            self.refresh()
            return
        self._busy.add("firewall")
        self._set_pending("firewall")
        try:
            ok = await self._engine.toggle_incoming_block()
        finally:
            self._busy.discard("firewall")
        if not ok:
            self._show_error(self._engine.firewall_error()
                             or self._state.t("fw_msg_failed"))
        else:
            self._show_info(self._state.t(
                "fw_msg_shield_off" if state.incoming_blocked
                else "fw_msg_shield_on"))
        self.refresh()

    # ── refresh ───────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Repaint from cached state, and kick off a live firewall re-read."""
        self._paint()
        asyncio.ensure_future(self._refresh_firewall())

    async def _refresh_firewall(self) -> None:
        try:
            self._fw_state = await self._engine.firewall_state()
        except Exception:
            self._fw_state = None
        self._paint()

    def _paint(self) -> None:
        states = self._engine.module_states()
        fw = self._fw_state
        s = self._state

        for key, row in self._rows.items():
            if key in self._busy:
                continue
            detail = ""
            if key == "fw_backend":
                if fw is None or not fw.installed:
                    active, status = False, s.t("status_unavailable")
                    detail = s.t("fw_detail_missing")
                else:
                    active = fw.running
                    status = s.t("status_running" if active else "status_stopped")
                    detail = (f"{s.t('fw_detail_zone')}: {fw.zone}" if fw.zone else "")
                    if fw.running and fw.enabled_known and not fw.enabled:
                        detail += ("  ·  " if detail else "") + s.t("fw_detail_not_boot")
                    if fw.panic:
                        detail += ("  ·  " if detail else "") + s.t("fw_detail_panic")
            elif key == "firewall":
                if fw is None or not fw.running:
                    active, status = False, s.t("status_unavailable")
                    detail = s.t("fw_detail_needs_fw")
                else:
                    active = fw.incoming_blocked
                    status = s.t("status_active" if active else "status_inactive")
                    n = (len(fw.rules.get("ips", []))
                         + len(fw.rules.get("ports_tcp", []))
                         + len(fw.rules.get("ports_udp", [])))
                    detail = f"{n} {s.t('fw_detail_rules')}"
            else:
                active = states.get(key, False)
                status = s.t("status_active" if active else "status_inactive")

            row.status.setText(status)
            row.status.setStyleSheet(
                f"color: {'#00e676' if active else '#555555'}; font-size: 12px;"
            )
            row.detail.setText(detail)
            row.detail.setVisible(bool(detail))
            row.btn.setText("●" if active else "○")
            row.btn.setProperty("active", active)
            _polish(row.btn)

    def _set_pending(self, key: str) -> None:
        row = self._rows.get(key)
        if row:
            row.status.setText(self._state.t("status_working"))
            row.status.setStyleSheet("color: #ffab00; font-size: 12px;")

    # ── messages ──────────────────────────────────────────────────────────

    def _show_error(self, text: str) -> None:
        self._msg.setText("⚠  " + text)
        self._msg.setStyleSheet(
            "font-size: 12px; color: #ff3d00; padding: 6px 24px;")

    def _show_info(self, text: str) -> None:
        self._msg.setText(text)
        self._msg.setStyleSheet(
            "font-size: 12px; color: #888; padding: 6px 24px;")

    def _confirm(self, title: str, body: str) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(body)
        box.setStandardButtons(QMessageBox.StandardButton.Yes
                               | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    # ── i18n ──────────────────────────────────────────────────────────────

    def retranslate(self, _lang: str = None) -> None:
        for key, row in self._rows.items():
            i18n_key = next(m[1] for m in MODULES if m[0] == key)
            row.name.setText(self._state.t(i18n_key))
            if key == "fw_backend":
                row.btn.setToolTip(self._state.t("tip_fw_backend"))
            elif key == "firewall":
                row.btn.setToolTip(self._state.t("tip_fw_shield"))
        self._msg.setText("")
        self._paint()
