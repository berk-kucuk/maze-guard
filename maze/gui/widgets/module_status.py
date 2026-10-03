import asyncio
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QScrollArea, QFrame, QHBoxLayout,
    QLabel, QPushButton, QMessageBox,
)
from PyQt6.QtCore import Qt

from maze.core.verify import FAIL, INFO, NA, PASS, WARN, Verdict
from maze.gui.theme import THREAT_COLORS
from maze.gui.widgets.common import ToggleSwitch, chip, set_chip

# Colour and one-word label per verdict. The label answers the question the
# button asks — "is this in effect?" — rather than restating Active/Inactive,
# which is the claim the test exists to check.
_VERDICT_STYLE = {
    PASS: ("#00e676", "verify_pass"),
    FAIL: ("#ff3d00", "verify_fail"),
    WARN: ("#ffab00", "verify_warn"),
    INFO: ("#8a8a8a", "verify_info"),
    NA:   ("#666666", "verify_na"),
}


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


class _Row:
    """One module line: name, sub-caption, status word and toggle."""

    def __init__(self, name_lbl: QLabel, detail_lbl: QLabel,
                 status_lbl: QLabel, test_btn: QPushButton, btn: ToggleSwitch):
        self.name = name_lbl
        self.detail = detail_lbl
        self.status = status_lbl
        self.test = test_btn
        self.btn = btn


class ModuleStatusWidget(QWidget):
    def __init__(self, state, engine):
        super().__init__()
        self._state = state
        self._engine = engine
        self._rows: dict[str, _Row] = {}
        self._fw_state = None
        self._busy: set[str] = set()
        self._testing: set[str] = set()
        # Last self-test result per module. Shown in place of the module's own
        # description, because a fact checked against the system outranks a
        # module's account of itself — and cleared the moment the toggle moves,
        # since it then describes a state that no longer exists.
        self._verdicts: dict[str, Verdict] = {}
        self._cat_labels: dict[str, QLabel] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._make_toolbar())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        self._inner = QVBoxLayout(container)
        self._inner.setContentsMargins(24, 8, 24, 20)
        self._inner.setSpacing(14)

        scroll.setWidget(container)

        # Results of a toggle or a self-test. Above the list, where it is
        # seen, rather than under a long scroll.
        self._msg = QLabel("")
        self._msg.setWordWrap(True)
        self._msg.setVisible(False)
        self._msg.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        msg_wrap = QHBoxLayout()
        msg_wrap.setContentsMargins(24, 0, 24, 6)
        msg_wrap.addWidget(self._msg)
        layout.addLayout(msg_wrap)
        layout.addWidget(scroll, 1)

        self._build_rows()
        state.language_changed.connect(self.retranslate)
        self.refresh()

    # ── build ─────────────────────────────────────────────────────────────

    def _build_rows(self) -> None:
        current_cat = None
        body = None
        first_in_card = True

        for key, i18n_key, cat_key in MODULES:
            if cat_key != current_cat:
                current_cat = cat_key
                body = self._add_category_card(cat_key)
                first_in_card = True

            name_lbl = QLabel(self._state.t(i18n_key))
            name_lbl.setStyleSheet("font-size: 14px; font-weight: 600;")

            detail_lbl = QLabel("")
            detail_lbl.setObjectName("muted")
            # Verdicts are written as sentences, not status codes. Without
            # wrapping, one of them widens the whole page.
            detail_lbl.setWordWrap(True)

            status_lbl = chip()
            status_lbl.setMinimumWidth(84)
            status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            test_btn = QPushButton(self._state.t("verify_btn"))
            test_btn.setToolTip(self._state.t("tip_verify"))
            test_btn.clicked.connect(lambda _, k=key: self._test(k))

            btn = ToggleSwitch()
            btn.clicked.connect(lambda _c, k=key: self._toggle(k))

            if key == "fw_backend":
                btn.setToolTip(self._state.t("tip_fw_backend"))
            elif key == "firewall":
                btn.setToolTip(self._state.t("tip_fw_shield"))

            self._rows[key] = _Row(name_lbl, detail_lbl, status_lbl,
                                   test_btn, btn)

            text_col = QVBoxLayout()
            text_col.setContentsMargins(0, 0, 0, 0)
            text_col.setSpacing(1)
            text_col.addWidget(name_lbl)
            text_col.addWidget(detail_lbl)

            if not first_in_card:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.HLine)
                body.addWidget(sep)
            first_in_card = False

            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 8, 0, 8)
            row_layout.setSpacing(14)
            row_layout.addLayout(text_col, 1)
            row_layout.addWidget(status_lbl)
            row_layout.addWidget(test_btn)
            row_layout.addWidget(btn)
            body.addWidget(row_widget)

        self._inner.addStretch()

    def _add_category_card(self, cat_key: str) -> QVBoxLayout:
        frame = QFrame()
        frame.setObjectName("card")
        body = QVBoxLayout(frame)
        body.setContentsMargins(18, 12, 18, 8)
        body.setSpacing(0)
        lbl = QLabel(self._state.t(cat_key).upper())
        lbl.setObjectName("card_title")
        body.addWidget(lbl)
        self._cat_labels[cat_key] = lbl
        self._inner.addWidget(frame)
        return body

    def _make_toolbar(self) -> QWidget:
        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(24, 16, 24, 8)
        row.setSpacing(12)

        self._toolbar_hint = QLabel(self._state.t("verify_hint"))
        self._toolbar_hint.setWordWrap(True)
        self._toolbar_hint.setObjectName("muted")
        row.addWidget(self._toolbar_hint, 1)

        self._test_all_btn = QPushButton(self._state.t("verify_all_btn"))
        self._test_all_btn.setFixedHeight(30)
        self._test_all_btn.setToolTip(self._state.t("tip_verify_all"))
        self._test_all_btn.clicked.connect(
            lambda: asyncio.ensure_future(self._run_all_tests()))
        row.addWidget(self._test_all_btn)
        return bar

    # ── self-tests ────────────────────────────────────────────────────────

    def _test(self, key: str) -> None:
        if key in self._testing:
            return
        asyncio.ensure_future(self._run_test(key))

    async def _run_test(self, key: str) -> Verdict:
        self._testing.add(key)
        row = self._rows[key]
        row.test.setEnabled(False)
        row.detail.setText(self._state.t("verify_running"))
        row.detail.setStyleSheet(f"color: {THREAT_COLORS['suspicious']};")
        row.detail.setVisible(True)
        try:
            verdict = await self._engine.verify_module(key)
        except Exception as exc:
            verdict = Verdict(FAIL, str(exc))
        finally:
            self._testing.discard(key)
            row.test.setEnabled(True)
        self._verdicts[key] = verdict
        self._show_verdict(key, verdict)
        self._paint()
        return verdict

    async def _run_all_tests(self) -> None:
        self._test_all_btn.setEnabled(False)
        self._show_info(self._state.t("verify_all_running"))
        tally = {PASS: 0, INFO: 0, WARN: 0, FAIL: 0, NA: 0}
        try:
            # One at a time: several of these open sockets or query the helper,
            # and running them together would produce a burst that looks rather
            # like the activity the application is built to notice.
            for key, _i18n, _cat in MODULES:
                verdict = await self._run_test(key)
                tally[verdict.status] = tally.get(verdict.status, 0) + 1
        finally:
            self._test_all_btn.setEnabled(True)
        # INFO is deliberately not folded into "in effect". A module with
        # nothing to enforce yet is not protecting anything, and a tally that
        # says otherwise is the same overstatement the Test button exists to
        # remove — just moved down one line.
        summary = (self._state.t("verify_summary")
                   .replace("{pass}", str(tally[PASS]))
                   .replace("{info}", str(tally[INFO]))
                   .replace("{warn}", str(tally[WARN] + tally[NA]))
                   .replace("{fail}", str(tally[FAIL])))
        if tally[FAIL]:
            self._show_error(summary)
        else:
            self._show_info(summary)

    def _show_verdict(self, key: str, verdict: Verdict) -> None:
        text = f"{self._name_of(key)} — {verdict.summary}"
        if verdict.evidence:
            text += "\n" + "\n".join(f"    · {e}" for e in verdict.evidence)
        if verdict.status == FAIL:
            self._show_error(text)
        else:
            self._show_info(text)

    # ── toggling ──────────────────────────────────────────────────────────

    def _toggle(self, key: str) -> None:
        if key in self._busy:
            self._paint()
            return
        if key == "fw_backend":
            asyncio.ensure_future(self._toggle_fw_backend())
        elif key == "firewall":
            asyncio.ensure_future(self._toggle_shield())
        else:
            asyncio.ensure_future(self._toggle_module(key))

    async def _toggle_module(self, key: str) -> None:
        # The previous verdict described the state we are about to leave.
        self._verdicts.pop(key, None)
        self._busy.add(key)
        self._set_pending(key)
        try:
            await self._engine.toggle_module(key)
        finally:
            self._busy.discard(key)
        # A module that refuses to start used to leave the toggle flicking
        # straight back to off with the reason buried in a log file. Say it.
        if not self._engine.module_states().get(key, False):
            reason = self._engine.module_error(key)
            if reason:
                self._show_error(f"{self._name_of(key)}: {reason}")
            else:
                self._show_info("")
        else:
            self._show_info("")
        self.refresh()

    def _name_of(self, key: str) -> str:
        return self._state.t(next(m[1] for m in MODULES if m[0] == key))

    async def _toggle_fw_backend(self) -> None:
        # max_age=0: never decide whether to stop the firewall, or what to warn
        # the user about, from a cached reading.
        state = await self._engine.firewall_state(max_age=0)
        if not state.installed:
            self._show_error(self._state.t("fw_msg_missing"))
            self._paint()           # the switch already flipped under the click
            return
        if state.running:
            # Turning the firewall off leaves the host exposed — never do it on
            # a single mis-click; make the consequence explicit first.
            if not self._confirm(self._state.t("fw_confirm_title"),
                                 self._state.t("fw_confirm_body")):
                self._paint()
                return
        self._verdicts.pop("fw_backend", None)
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
        self._verdicts.pop("firewall", None)
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
            if key in self._busy or key in self._testing:
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
                if active:
                    # What a running module is actually doing. "Active" alone
                    # is exactly the reassurance a module that has gone blind
                    # — a rogue-AP watcher on a wired link, a blocker whose
                    # rules never reached the firewall — must not be able to
                    # give.
                    detail = self._engine.module_detail(key)
                else:
                    reason = self._engine.module_error(key)
                    if reason:
                        status = s.t("status_unavailable")
                        detail = reason

            unavailable = status == s.t("status_unavailable")
            set_chip(row.status, status,
                     THREAT_COLORS["safe"] if active
                     else THREAT_COLORS["suspicious"] if unavailable
                     else "#8b919a")

            # A verdict outranks the module's own description of itself: it was
            # checked against the system, and that is the whole point of it.
            verdict = self._verdicts.get(key)
            if verdict is not None:
                colour, label_key = _VERDICT_STYLE.get(
                    verdict.status, _VERDICT_STYLE[NA])
                row.detail.setText(f"{s.t(label_key)} — {verdict.summary}")
                row.detail.setStyleSheet(f"color: {colour};")
                row.detail.setToolTip("\n".join(verdict.evidence))
                row.detail.setVisible(True)
            else:
                # With nothing more specific to say, say what the module is for.
                row.detail.setText(detail or s.t(f"desc_{key}"))
                row.detail.setStyleSheet("")
                row.detail.setToolTip("")
                row.detail.setVisible(True)
            row.btn.set_busy(False)
            row.btn.set_state(active)

    def _set_pending(self, key: str) -> None:
        row = self._rows.get(key)
        if row:
            set_chip(row.status, self._state.t("status_working"),
                     THREAT_COLORS["suspicious"])
            row.btn.set_busy(True)

    # ── messages ──────────────────────────────────────────────────────────

    def _show_error(self, text: str) -> None:
        self._show_banner("⚠  " + text, THREAT_COLORS["dangerous"])

    def _show_info(self, text: str) -> None:
        self._show_banner(text, "")

    def _show_banner(self, text: str, color: str) -> None:
        self._msg.setVisible(bool(text))
        self._msg.setText(text)
        tint = (f"color: {color}; border: 1px solid {color};" if color
                else "border: 1px solid rgba(128,128,128,90);")
        self._msg.setStyleSheet(f"{tint} border-radius: 8px; padding: 8px 12px;")

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
        self._toolbar_hint.setText(self._state.t("verify_hint"))
        self._test_all_btn.setText(self._state.t("verify_all_btn"))
        self._test_all_btn.setToolTip(self._state.t("tip_verify_all"))
        for key, row in self._rows.items():
            i18n_key = next(m[1] for m in MODULES if m[0] == key)
            row.name.setText(self._state.t(i18n_key))
            row.test.setText(self._state.t("verify_btn"))
            row.test.setToolTip(self._state.t("tip_verify"))
            if key == "fw_backend":
                row.btn.setToolTip(self._state.t("tip_fw_backend"))
            elif key == "firewall":
                row.btn.setToolTip(self._state.t("tip_fw_shield"))
        for cat_key, lbl in self._cat_labels.items():
            lbl.setText(self._state.t(cat_key).upper())
        self._show_info("")
        self._paint()
