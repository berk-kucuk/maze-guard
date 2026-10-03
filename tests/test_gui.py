"""
End-to-end tests of the interface.

The real window is built offscreen around a real engine; the privileged
helper is the real helper code running in-process against a simulated
firewalld (tests/support/fake_firewalld.py). So a click on "Block" travels
the same path as on a desktop — widget → engine → firewall manager → helper
validation → firewall-cmd — and only the last process is pretend.

    QT_QPA_PLATFORM=offscreen ./venv/bin/python -m unittest tests.test_gui -v
"""
import asyncio
import csv
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")
os.environ["QT_API"] = "pyqt6"

try:
    from PyQt6.QtWidgets import QApplication, QMessageBox, QFileDialog, QInputDialog
    import qasync
except Exception:                                  # pragma: no cover
    QApplication = None

from maze.core.events import Event, EventType, ThreatLevel     # noqa: E402
from maze.core.profile import Profile                          # noqa: E402

_app = None
_loop = None


def setUpModule():
    global _app, _loop
    if QApplication is None:
        raise unittest.SkipTest("PyQt6 / qasync not installed")
    _app = QApplication.instance() or QApplication([])
    _loop = qasync.QEventLoop(_app)


def run(coro, timeout: float = 20.0):
    return _loop.run_until_complete(asyncio.wait_for(coro, timeout))


def settle(seconds: float = 0.05):
    run(asyncio.sleep(seconds))


async def until(predicate, timeout: float = 5.0, step: float = 0.05) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(step)
    return predicate()


# Modules that would reach the real network or radio from a test.
_OFFLINE = ("dns_validate", "tls", "rogue_ap")


class GuiTestBase(unittest.TestCase):
    language = "en"

    def setUp(self):
        # Other test modules use asyncio.run(), which leaves no current loop.
        asyncio.set_event_loop(_loop)
        run(self._setup())

    def tearDown(self):
        run(self._teardown())
        for p in reversed(self._patches):
            p.stop()
        self.tmp.cleanup()

    def _callTestMethod(self, method):
        # Everything a test does to the window happens inside the running
        # loop, as it does in the application.
        if asyncio.iscoroutinefunction(method):
            run(method(), timeout=60)
        else:
            method()

    async def _setup(self):
        from support.fake_firewalld import FakeFirewalld, InProcessHelper
        from maze.utils import config as config_mod
        from maze.gui import autostart
        from maze.gui.app_state import AppState
        from maze.gui.theme import get_stylesheet

        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self._patches = [
            unittest.mock.patch.object(config_mod, "CONFIG_PATH", tmp / "config.json"),
            unittest.mock.patch.object(autostart, "USER_PATH", tmp / "autostart.desktop"),
            unittest.mock.patch.object(autostart, "SYSTEM_PATH", tmp / "none.desktop"),
            unittest.mock.patch.dict(os.environ, {"MAZE_DATA_DIR": str(tmp / "data")}),
            # Stealth modules write crash-recovery files under ~/.config/maze;
            # a test must never leave one for the real application to "restore".
            unittest.mock.patch("maze.stealth.fingerprint._STATE_FILE", tmp / "fp-state"),
            unittest.mock.patch("maze.stealth.hostname_hide._STATE_FILE", tmp / "hh-state"),
            # Dialogs would block the test: answer them.
            unittest.mock.patch.object(QMessageBox, "question",
                                       return_value=QMessageBox.StandardButton.Yes),
            unittest.mock.patch.object(QMessageBox, "warning",
                                       return_value=QMessageBox.StandardButton.Ok),
        ]
        for p in self._patches:
            p.start()

        self.cfg = config_mod.MazeConfig(interface="lo", first_run_done=True)
        self.cfg.port_scan_threshold = 5
        self.fw = FakeFirewalld()
        self.helper = InProcessHelper(self.fw)
        from maze.core.engine import MazeEngine
        self.engine = MazeEngine(self.cfg, helper=self.helper)
        for key in _OFFLINE:
            mod = self.engine._modules[key]
            mod.start = unittest.mock.AsyncMock()
            mod.stop = unittest.mock.AsyncMock()

        self.state = AppState(theme="dark", language=self.language)
        _app.setStyleSheet(get_stylesheet("dark"))
        from maze.gui.dashboard import Dashboard
        self.win = Dashboard(self.engine, self.cfg, self.state)
        self.win.show()
        self.events: list[Event] = []

        async def collect(event):
            self.events.append(event)
        self.engine.bus.subscribe_all(collect)
        self.engine._running = True
        self.engine.bus.subscribe_all(self.engine._on_event_for_recon)
        await asyncio.sleep(0.05)

    async def _teardown(self):
        self.win._timer.stop()
        self.win.hide()
        await self.engine.stop()
        me = asyncio.current_task()
        for task in asyncio.all_tasks(_loop):
            if task is not me:
                task.cancel()
        await asyncio.sleep(0.05)
        self.win.deleteLater()
        await asyncio.sleep(0.05)

    # helpers
    async def page(self, attr: str):
        widget = getattr(self.win, attr)
        self.win._go(self.win.tabs.indexOf(widget))
        await asyncio.sleep(0.1)
        return widget

    async def emit(self, level, kind=EventType.ANOMALY, message="test", **data):
        await self.engine.bus.emit(Event(type=kind, level=level, message=message,
                                         data=data))


class NavigationTests(GuiTestBase):
    async def test_every_page_opens_and_titles_follow(self):
        for i in range(self.win.tabs.count()):
            self.win._go(i)
            await asyncio.sleep(0.05)
            self.assertEqual(self.win.tabs.currentIndex(), i)
            self.assertTrue(self.win._nav[i].isChecked())
            self.assertTrue(self.win._page_title.text())

    async def test_keyboard_shortcuts_switch_pages(self):
        from PyQt6.QtTest import QTest
        from PyQt6.QtCore import Qt
        QTest.keyClick(self.win, Qt.Key.Key_3, Qt.KeyboardModifier.ControlModifier)
        await asyncio.sleep(0.05)
        self.assertIs(self.win.tabs.currentWidget(), self.win.event_list)
        QTest.keyClick(self.win, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
        await asyncio.sleep(0.05)
        self.assertTrue(self.win.event_list._search.hasFocus())

    async def test_notification_contexts_open_their_pages(self):
        for ctx, attr in (("threats", "threats_view"), ("devices", "device_list"),
                          ("events", "event_list"), ("firewall", "firewall_view"),
                          ("protection", "module_status"), ("settings", "settings_view")):
            self.win._open_context(ctx)
            self.assertIs(self.win.tabs.currentWidget(), getattr(self.win, attr))

    async def test_overview_tiles_navigate(self):
        await self.page("dash_view")
        self.win.dash_view._tile_devices._on_click()
        self.assertIs(self.win.tabs.currentWidget(), self.win.device_list)

    async def test_language_switch_retranslates_everything(self):
        self.state.set_language("tr")
        await asyncio.sleep(0.05)
        self.assertEqual(self.win._nav[0].text(), "Panel")
        self.assertEqual(self.win.settings_view._grp_appearance.title(), "Görünüm")
        self.assertEqual(self.win.event_list._btn_all.text(), "Tümü")
        self.state.set_theme("light")
        await asyncio.sleep(0.05)
        self.assertIn("#f4f5f7", _app.styleSheet())


class FirewallPageTests(GuiTestBase):
    async def test_block_and_unblock_an_address_through_the_real_helper(self):
        view = await self.page("firewall_view")
        view._ip_input.setText("192.168.1.77")
        view._add_ip()
        self.assertTrue(await until(lambda: self.fw.has("192.168.1.77")))
        await until(lambda: view._ip_table.rowCount() == 1)
        self.assertEqual(view._ip_table.item(0, 0).text(), "192.168.1.77")
        # The rule carries the audit log clause and passed helper validation.
        self.assertTrue(self.fw.has("log prefix=MAZE-BLOCK"))
        view._ip_table.cellWidget(0, 2).click()
        self.assertTrue(await until(lambda: not self.fw.has("192.168.1.77")))
        self.assertIn("remove a block on an attacker", self.helper.consent_asked)

    async def test_ipv6_and_ranges_are_accepted_but_too_broad_is_refused(self):
        view = await self.page("firewall_view")
        view._ip_input.setText("fe80::1234")
        view._add_ip()
        self.assertTrue(await until(lambda: self.fw.has("family=ipv6 source address=fe80::1234")))
        view._ip_input.setText("10.0.0.0/4")
        view._add_ip()
        await asyncio.sleep(0.2)
        self.assertFalse(self.fw.has("10.0.0.0/4"))
        view._ip_input.setText("not-an-ip")
        view._add_ip()
        self.assertIn("not-an-ip", view._status_lbl.text())

    async def test_port_block_covers_both_families_and_unblock_removes_both(self):
        view = await self.page("firewall_view")
        view._port_input.setText("2222")
        view._proto_combo.setCurrentIndex(2)          # TCP + UDP
        view._add_port()
        self.assertTrue(await until(lambda: len(self.fw.rules) == 4))
        self.assertTrue(self.fw.has("family=ipv6 port port=2222 protocol=udp"))
        await until(lambda: view._port_table.rowCount() == 2)
        await view._unblock_port(2222, "tcp")
        self.assertFalse(self.fw.has("protocol=tcp"))
        self.assertTrue(self.fw.has("protocol=udp"))
        view._port_input.setText("70000")
        view._add_port()
        self.assertIn("65535", view._status_lbl.text())

    async def test_clear_all_removes_every_rule(self):
        await self.engine.block_ip("192.168.1.5")
        await self.engine.block_port(8080, "tcp")
        await self.engine.firewall.block_mac("aa:bb:cc:dd:ee:ff")
        view = await self.page("firewall_view")
        await until(lambda: view._ip_table.rowCount() == 2)
        view._flush_all()
        self.assertTrue(await until(lambda: not self.fw.rules))

    async def test_mac_blocks_are_listed_and_removable(self):
        await self.engine.firewall.block_mac("aa:bb:cc:dd:ee:ff")
        view = await self.page("firewall_view")
        await until(lambda: view._ip_table.rowCount() == 1)
        self.assertEqual(view._ip_table.item(0, 0).text(), "aa:bb:cc:dd:ee:ff")
        view._ip_table.cellWidget(0, 2).click()
        self.assertTrue(await until(lambda: not self.fw.rules))

    def external_change(self):
        """firewalld changed behind our back (another tool, another admin)."""
        self.engine._fw_state_at = 0.0

    async def test_controls_are_disabled_while_firewalld_is_stopped(self):
        self.fw.running = False
        self.external_change()
        view = await self.page("firewall_view")
        await view._async_refresh()
        self.assertFalse(view._ip_btn.isEnabled())
        self.assertFalse(view._flush_btn.isEnabled())


class ProtectionPageTests(GuiTestBase):
    async def test_a_module_switch_turns_it_on_and_off(self):
        view = await self.page("module_status")
        switch = view._rows["anomaly"].btn
        self.assertFalse(switch.isChecked())
        switch.click()
        self.assertTrue(await until(lambda: self.engine.module_states()["anomaly"]))
        await until(lambda: switch.isChecked() and switch.isEnabled())
        switch.click()
        self.assertTrue(await until(lambda: not self.engine.module_states()["anomaly"]))

    async def test_stealth_modules_work_through_the_helper(self):
        view = await self.page("module_status")
        for key in ("hostname", "fingerprint", "service_blocker"):
            view._rows[key].btn.click()
            self.assertTrue(await until(lambda k=key: self.engine.module_states()[k]),
                            f"{key}: {self.engine.module_error(key)}")
        self.assertFalse(self.fw.units["avahi-daemon"])
        self.assertEqual(self.fw.sysctl["net.ipv4.ip_default_ttl"], "128")
        self.assertTrue(self.fw.has("port port=5353 protocol=udp"))
        for key in ("hostname", "fingerprint", "service_blocker"):
            view._rows[key].btn.click()
            await until(lambda k=key: not self.engine.module_states()[k])
        self.assertTrue(self.fw.units["avahi-daemon"])
        self.assertEqual(self.fw.sysctl["net.ipv4.ip_default_ttl"], "64")
        self.assertFalse(self.fw.rules)

    async def test_firewall_backend_and_shield_switches(self):
        view = await self.page("module_status")
        view._confirm = lambda *_a: True
        await view._toggle_shield()
        self.assertEqual(self.fw.target, "DROP")
        await view._toggle_shield()
        self.assertEqual(self.fw.target, "default")
        await view._toggle_fw_backend()
        self.assertFalse(self.fw.running)
        await view._toggle_fw_backend()
        self.assertTrue(self.fw.running)

    async def test_cancelling_the_stop_confirmation_keeps_the_firewall(self):
        view = await self.page("module_status")
        view._confirm = lambda *_a: False
        await view._refresh_firewall()
        await view._toggle_fw_backend()
        self.assertTrue(self.fw.running)
        self.assertTrue(view._rows["fw_backend"].btn.isChecked())

    async def test_declined_consent_reports_an_error(self):
        self.helper.consent = False
        self.fw.target = "DROP"
        view = await self.page("module_status")
        await view._toggle_shield()
        self.assertEqual(self.fw.target, "DROP")
        self.assertIn("⚠", view._msg.text())

    async def test_test_buttons_produce_verdicts(self):
        view = await self.page("module_status")
        verdict = await asyncio.wait_for(view._run_test("port_scan"), 30)
        self.assertTrue(view._rows["port_scan"].detail.text())
        self.assertIn(verdict.status, ("pass", "info", "warn", "fail", "n/a",
                                       verdict.status))
        verdict = await view._run_test("fw_backend")
        self.assertEqual(verdict.status, "pass", verdict.summary)


class DetectionToBlockTests(GuiTestBase):
    """A scan arriving from the capture ends as a firewall rule and a dossier."""

    async def test_a_port_scan_is_detected_blocked_and_shown(self):
        from maze.utils.recon import ReconResult
        await self.engine._apply_plan(["firewall", "port_scan"], False, "test", "test")
        attacker = "192.168.1.66"

        async def fake_recon(ip, *a, **k):
            return ReconResult(ip=ip, mac="aa:bb:cc:11:22:33")

        with unittest.mock.patch("maze.utils.recon.recon_ip", fake_recon), \
             unittest.mock.patch.object(type(self.engine), "_infra_ips",
                                        lambda _self: set()):
            async def scan():
                for port in range(2000, 2030):
                    await self.helper.push({"event": "tcp", "src": attacker,
                                            "dst": "", "dport": port, "flags": "S"})
            await scan()
            self.assertTrue(await until(lambda: self.fw.has(attacker)))

        kinds = {e.type for e in self.events}
        self.assertIn(EventType.PORT_SCAN, kinds)
        self.assertIn(EventType.IP_BLOCKED, kinds)
        att = self.engine.incidents.get(attacker)
        self.assertTrue(att and att.blocked)

        threats = await self.page("threats_view")
        self.assertEqual(threats._table.rowCount(), 1)
        self.assertTrue(threats.select(attacker))
        self.assertIn(attacker, threats._detail.toPlainText())
        self.assertEqual(self.win.threat_widget._level, ThreatLevel.DANGEROUS)
        self.assertTrue(self.win._threat_badge.isVisible())

        # The Threats page unblocks it again.
        threats._toggle_block()
        self.assertTrue(await until(lambda: not self.fw.has(attacker)))
        self.assertFalse(self.engine.incidents.get(attacker).blocked)

        # Events → double-click opens the dossier.
        events = await self.page("event_list")
        row = next(r for r in range(events._table.rowCount())
                   if events._event_at(r).type == EventType.PORT_SCAN)
        events._open_row(row)
        self.assertIs(self.win.tabs.currentWidget(), threats)

    async def test_whitelisted_sources_are_never_reported(self):
        await self.engine._apply_plan(["port_scan"], False, "test", "test")
        self.win.settings_view._add_whitelist("192.168.1.0/24")

        async def scan():
            for port in range(3000, 3030):
                await self.helper.push({"event": "tcp", "src": "192.168.1.66",
                                        "dst": "", "dport": port, "flags": "S"})
        await scan()
        await asyncio.sleep(0.2)
        self.assertNotIn(EventType.PORT_SCAN, {e.type for e in self.events})


class NotificationTests(GuiTestBase):
    """What pops up on the desktop, when, and where clicking it leads."""

    async def _setup(self):
        await super()._setup()
        import maze.gui.dashboard as dash
        from maze.utils.recon import ReconResult
        self.popups: list[tuple] = []
        tray = self.win._tray
        tray.notify_danger = lambda t, b, context="": self.popups.append(("danger", t, b, context))
        tray.notify_warning = lambda t, b, context="": self.popups.append(("warn", t, b, context))
        self._extra = [
            unittest.mock.patch.object(dash, "_COALESCE_MS", 200),
            unittest.mock.patch("maze.utils.recon.recon_ip",
                                unittest.mock.AsyncMock(side_effect=lambda ip, *a, **k:
                                                        ReconResult(ip=ip))),
            unittest.mock.patch.object(type(self.engine), "_infra_ips",
                                       lambda _self: set()),
        ]
        for p in self._extra:
            p.start()
        await self.engine._apply_plan(["firewall"], False, "test", "test")

    async def _teardown(self):
        for p in reversed(self._extra):
            p.stop()
        await super()._teardown()

    def scan(self, src, level=ThreatLevel.DANGEROUS):
        return self.emit(level, EventType.PORT_SCAN, f"Port scan from {src}", src=src)

    async def test_an_attack_that_is_blocked_is_one_notification(self):
        await self.scan("192.168.1.66")
        await until(lambda: self.fw.has("192.168.1.66"))
        await asyncio.sleep(0.4)
        self.assertEqual(len(self.popups), 1, self.popups)
        kind, title, body, context = self.popups[0]
        self.assertEqual(kind, "danger")
        self.assertEqual(title, "Attack blocked: Port scan")
        self.assertIn("blocked the source automatically", body)
        self.assertEqual(context, "threats")

    async def test_without_auto_block_the_attack_still_pops(self):
        self.cfg.auto_block = False
        await self.scan("192.168.1.67")
        await asyncio.sleep(0.4)
        self.assertEqual([p[1] for p in self.popups], ["Threat: Port scan"])
        self.assertFalse(self.fw.rules)

    async def test_an_escalation_is_announced(self):
        self.cfg.notify_min_level = "suspicious"
        self.cfg.auto_block = False
        await self.scan("192.168.1.68", ThreatLevel.SUSPICIOUS)
        await self.scan("192.168.1.68", ThreatLevel.DANGEROUS)
        await asyncio.sleep(0.4)
        self.assertEqual([p[0] for p in self.popups], ["warn", "danger"])

    async def test_suspicious_noise_cannot_crowd_out_a_real_attack(self):
        self.cfg.notify_min_level = "suspicious"
        for i in range(5):
            await self.emit(ThreatLevel.SUSPICIOUS, EventType.HOST_SWEEP,
                            f"sweep {i}", src=f"192.168.1.{100 + i}")
        await self.emit(ThreatLevel.DANGEROUS, EventType.ARP_SPOOF,
                        "ARP spoofing", ip="192.168.1.1", src="192.168.1.77",
                        mac="ee:ee:ee:ee:ee:66")
        self.assertEqual([p[0] for p in self.popups].count("warn"), 3)
        self.assertEqual(self.popups[-1][:2], ("danger", "Threat: ARP spoofing"))
        # Filed under the impersonator, so the click opens its dossier.
        self.assertEqual(self.popups[-1][3], "threats")
        self.assertIsNone(self.engine.incidents.get("192.168.1.1"))

    async def test_own_actions_and_follow_ups_stay_quiet(self):
        self.cfg.notify_min_level = "suspicious"
        rows = self.win.event_list._table.rowCount()
        for kind in (EventType.FIREWALL_CHANGED, EventType.RECON_RESULT,
                     EventType.IP_MOVED, EventType.MODULE_TOGGLED):
            await self.emit(ThreatLevel.SUSPICIOUS, kind, "x", ip="192.168.1.9")
        self.assertEqual(self.popups, [])
        self.assertEqual(self.win._threat_level, ThreatLevel.SAFE)
        self.assertEqual(self.win.event_list._table.rowCount(), rows + 4)

    async def test_no_attacker_means_the_event_list(self):
        self.cfg.notify_min_level = "suspicious"
        await self.emit(ThreatLevel.SUSPICIOUS, EventType.DNS_LEAK,
                        "Unexpected DNS server", ip="8.8.8.8")
        self.assertEqual(self.popups[0][3], "events")
        self.assertIsNone(self.engine.incidents.get("8.8.8.8"))

    async def test_off_means_nothing_pops_up(self):
        self.cfg.notify_min_level = "off"
        self.engine.profiles.current = Profile.HOME
        await self.emit(ThreatLevel.SUSPICIOUS, EventType.DEVICE_NEW, "new device",
                        ip="192.168.1.80", network_id="wifi:Home")
        await self.emit(ThreatLevel.DANGEROUS, EventType.ARP_SPOOF, "spoof",
                        ip="192.168.1.1", src="192.168.1.77")
        self.assertEqual(self.popups, [])
        # The events are still recorded and the header still reacts.
        self.assertEqual(self.win._threat_level, ThreatLevel.DANGEROUS)

    async def test_titles_are_translated(self):
        self.state.set_language("tr")
        self.cfg.auto_block = False
        await self.scan("192.168.1.69")
        await asyncio.sleep(0.4)
        self.assertEqual(self.popups[0][1], "Tehdit: Port taraması")


class EventsPageTests(GuiTestBase):
    async def _fill(self):
        for i in range(9):
            level = (ThreatLevel.SAFE, ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS)[i % 3]
            # ANOMALY, not PORT_SCAN: an active attack would (correctly)
            # trigger auto-block and add IP_BLOCKED rows of its own.
            await self.emit(level, EventType.ANOMALY, f"probe {i} from 10.0.0.{i}",
                            src=f"10.0.0.{i}")

    def visible(self, view):
        return [r for r in range(view._table.rowCount()) if not view._table.isRowHidden(r)]

    async def test_filters_search_and_language_switch(self):
        view = await self.page("event_list")
        await self._fill()
        view._set_level_filter(ThreatLevel.DANGEROUS)
        self.assertEqual(len(self.visible(view)), 3)
        self.state.set_language("tr")
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.visible(view)), 3)
        self.assertEqual(view._table.item(self.visible(view)[0], 2).text(), "Anormallik")
        view._set_level_filter(None)
        view._search.setText("probe 4")
        self.assertEqual(len(self.visible(view)), 1)
        view._search.setText("")
        self.assertFalse(view._empty.label.isVisible())

    async def test_selection_explains_and_export_writes_csv(self):
        view = await self.page("event_list")
        await self._fill()
        view._table.selectRow(0)
        self.assertTrue(view._explain.toPlainText())
        out = Path(self.tmp.name) / "events.csv"
        with unittest.mock.patch.object(QFileDialog, "getSaveFileName",
                                        return_value=(str(out), "")):
            view._export_csv()
        rows = list(csv.reader(out.open()))
        self.assertEqual(len(rows), 1 + view._table.rowCount())

    async def test_clear_and_counts(self):
        view = await self.page("event_list")
        await self._fill()
        counts = view.level_counts()
        self.assertEqual(counts[ThreatLevel.DANGEROUS], 3)
        view._clear_events()
        self.assertEqual(view._table.rowCount(), 0)
        self.assertTrue(view._empty.label.isVisible())

    async def test_the_list_is_bounded(self):
        from maze.gui.widgets import event_list
        view = await self.page("event_list")
        with unittest.mock.patch.object(event_list, "_MAX_ROWS", 5):
            for i in range(8):
                view.add_event(Event(type=EventType.ANOMALY, level=ThreatLevel.SUSPICIOUS,
                                     message=f"m{i}"))
        self.assertEqual(view._table.rowCount(), 5)
        self.assertEqual(view._event_at(4).message, "m7")


class OverviewTests(GuiTestBase):
    async def test_hero_follows_the_situation(self):
        view = await self.page("dash_view")
        await view._refresh_async()
        self.assertEqual(view._hero_title.text(), self.state.t("hero_ok_title"))
        self.fw.running = False
        self.engine._fw_state_at = 0.0          # changed outside the app
        await view._refresh_async()
        self.assertEqual(view._hero_title.text(), self.state.t("hero_fw_off_title"))
        self.helper._connected = False
        await view._refresh_async()
        self.assertEqual(view._hero_title.text(), self.state.t("hero_limited_title"))
        self.helper._connected = True
        self.fw.running = True
        self.engine._fw_state_at = 0.0
        await self.emit(ThreatLevel.DANGEROUS, EventType.ARP_SPOOF, "spoof", ip="192.168.1.1")
        self.assertEqual(view._hero_title.text(), self.state.t("hero_danger_title"))
        view._hero_btn.click()
        self.assertIs(self.win.tabs.currentWidget(), self.win.threats_view)
        self.win._reset_threat()
        await view._refresh_async()
        self.assertEqual(view._hero_title.text(), self.state.t("hero_ok_title"))

    async def test_an_outdated_helper_is_called_out(self):
        view = await self.page("dash_view")
        self.assertEqual(await self.helper.version(), 2)
        self.assertFalse(self.helper.outdated)
        self.helper.protocol = 0                 # a daemon that predates "version"
        await view._refresh_async()
        self.assertEqual(view._hero_title.text(), self.state.t("hero_outdated_title"))
        self.assertIn("restart", self.win.settings_view._about_text().lower())

    async def test_tiles_count_what_happened(self):
        view = await self.page("dash_view")
        await self.engine.block_ip("192.168.1.9")
        await self.emit(ThreatLevel.SUSPICIOUS, message="one")
        await self.emit(ThreatLevel.SAFE, message="two")
        await view._refresh_async()
        self.assertEqual(view._tile_blocked.value.text(), "1")
        self.assertEqual(view._tile_events.value.text(), "2")
        self.assertEqual(view._recent_table.rowCount(), 1)     # SAFE is not an alert


class ProfileTests(GuiTestBase):
    async def test_choosing_a_profile_applies_and_persists_it(self):
        from maze.utils.config import load_config
        self.win.profile_combo.setCurrentIndex(1)                  # Public
        self.assertTrue(await until(lambda: "hostname" in self.engine._active, 8))
        self.assertIn("fingerprint", self.engine._active)
        self.assertEqual(load_config().profile, "public")
        # Public raises the inbound shield.
        self.assertEqual(self.fw.target, "DROP")

    async def test_custom_profiles_create_select_edit_delete(self):
        from maze.utils.config import CustomProfileConfig, load_config
        sv = await self.page("settings_view")

        class FakeDialog:
            result_profile = CustomProfileConfig(name="Cafe", hide_hostname=True,
                                                 port_scan_detect=True)
            def __init__(self, *a, **k): pass
            def exec(self): return True

        with unittest.mock.patch("maze.gui.widgets.profile_dialog.ProfileDialog", FakeDialog):
            sv._new_profile()
        self.assertEqual(self.win.profile_combo.itemText(self.win.profile_combo.count() - 1), "Cafe")
        self.win.profile_combo.setCurrentIndex(self.win.profile_combo.count() - 1)
        self.assertTrue(await until(lambda: "hostname" in self.engine._active, 8))
        self.assertEqual(load_config().profile, "custom:Cafe")

        sv._profiles_list.setCurrentRow(0)
        FakeDialog.result_profile = CustomProfileConfig(name="Office")
        with unittest.mock.patch("maze.gui.widgets.profile_dialog.ProfileDialog", FakeDialog):
            sv._edit_profile()
        self.assertEqual(self.cfg.profile, "custom:Office")
        self.assertEqual(self.win.profile_combo.currentText(), "Office")

        sv._profiles_list.setCurrentRow(0)
        sv._delete_profile()
        self.assertEqual(self.cfg.custom_profiles, [])
        self.assertEqual(self.cfg.profile, "home")
        self.assertEqual(self.win.profile_combo.count(), 5)

    async def test_profile_dialog_validates_names(self):
        from maze.gui.widgets.profile_dialog import ProfileDialog
        dlg = ProfileDialog(self.state, taken={"Cafe"})
        dlg._save()
        self.assertIsNone(dlg.result_profile)
        dlg._name.setText("cafe")
        dlg._save()
        self.assertIsNone(dlg.result_profile)
        dlg._name.setText("Library")
        dlg._checks["block_services"].setChecked(True)
        dlg._save()
        self.assertTrue(dlg.result_profile.block_services)

    async def test_tray_menu_switches_profile(self):
        menu = self.win._tray._menu
        sub = next(a.menu() for a in menu.actions() if a.menu())
        sub.actions()[3].trigger()                                  # Secure
        await asyncio.sleep(0.05)
        self.assertEqual(self.cfg.profile, "secure")
        self.assertIn(self.state.t("threat_safe"), self.win._tray._tray.toolTip())


class SettingsTests(GuiTestBase):
    async def test_every_setting_reaches_the_config_file(self):
        from maze.utils.config import load_config
        sv = await self.page("settings_view")
        sv._notify_combo.setCurrentIndex(2)
        sv._threshold_spin.setValue(40)
        sv._newdev_cb.setChecked(False)
        sv._auto_block_cb.setChecked(False)
        sv._mac_block_cb.setChecked(False)
        sv._add_process("myapp")
        sv._add_whitelist("10.1.0.0/16")
        saved = load_config()
        self.assertEqual(saved.notify_min_level, "off")
        self.assertEqual(saved.port_scan_threshold, 40)
        self.assertEqual(self.engine._modules["port_scan"].threshold, 40)
        self.assertFalse(saved.notify_new_devices)
        self.assertFalse(saved.auto_block)
        self.assertFalse(saved.block_by_mac)
        self.assertIn("myapp", saved.known_processes)
        self.assertIn("myapp", self.engine._modules["process"]._known)
        self.assertIn("10.1.0.0/16", saved.whitelist_ips)
        self.assertIn("10.1.2.3", self.engine.whitelist)
        sv._remove_process("myapp")
        sv._remove_whitelist("10.1.0.0/16")
        self.assertNotIn("10.1.2.3", self.engine.whitelist)
        self.assertNotIn("myapp", load_config().known_processes)

    async def test_invalid_whitelist_entry_is_refused(self):
        sv = await self.page("settings_view")
        self.assertFalse(sv._add_whitelist("999.1.1.1"))
        self.assertEqual(self.cfg.whitelist_ips, [])

    async def test_appearance_combos_drive_the_app(self):
        sv = await self.page("settings_view")
        sv._lang.setCurrentIndex(sv._lang.findData("tr"))
        self.assertEqual(self.state.language, "tr")
        sv._theme.setCurrentIndex(sv._theme.findData("light"))
        self.assertEqual(self.state.theme, "light")

    async def test_trusted_networks_and_auto_switching(self):
        sv = await self.page("settings_view")
        self.engine.identity._network_id = "wifi:HomeNet"
        sv._trust_current_network()
        self.assertIn("wifi:HomeNet", self.cfg.trusted_networks)
        sv._auto_cb.setChecked(True)
        self.assertTrue(self.win._auto_watcher._enabled)
        sv._remove_trusted("wifi:HomeNet")
        self.assertEqual(self.cfg.trusted_networks, [])
        sv._auto_cb.setChecked(False)
        self.assertFalse(self.win._auto_watcher._enabled)

    async def test_autostart_toggle_writes_and_removes_the_entry(self):
        from maze.gui import autostart
        sv = await self.page("settings_view")
        sv._autostart_cb.setChecked(True)
        self.assertTrue(autostart.USER_PATH.exists())
        sv._autostart_cb.setChecked(False)
        self.assertFalse(autostart.USER_PATH.exists())


class DevicesAndConnectionsTests(GuiTestBase):
    async def _devices(self):
        from datetime import datetime
        watcher = self.engine.arp_watcher
        watcher.devices.clear()
        watcher.devices.update({
            "192.168.1.20": {"mac": "aa:aa:aa:00:00:01", "first_seen": datetime.now()},
            "192.168.1.21": {"mac": "aa:aa:aa:00:00:02", "first_seen": datetime.now()},
        })
        net = "wifi:HomeNet"
        self.engine.identity._network_id = net
        for ip, info in watcher.devices.items():
            self.engine.inventory.observe(info["mac"], ip, net)
        view = await self.page("device_list")
        view.update_devices(watcher.devices)
        return view

    async def test_devices_are_listed_and_buttons_act_on_the_selection(self):
        view = await self._devices()
        self.assertEqual(view._table.rowCount(), 2)
        self.assertFalse(view._btn_trust.isEnabled())
        view._table.selectRow(0)
        ip = view._selected_ip
        self.assertTrue(view._btn_trust.isEnabled())
        before = view._record(ip).trusted
        view._btn_trust.click()
        self.assertNotEqual(view._record(ip).trusted, before)
        with unittest.mock.patch.object(QInputDialog, "getText", return_value=("Printer", True)):
            view._btn_label.click()
        self.assertEqual(view._record(ip).label, "Printer")
        view._search.setText("Printer")
        self.assertEqual(view._table.rowCount(), 1)

    async def test_scan_button_gathers_information(self):
        view = await self._devices()
        view._table.selectRow(0)
        calls = []

        async def gather(ip, mac, force=False, profile="standard"):
            calls.append((ip, profile))
        view._cache.gather = gather
        view._btn_scan.click()
        await until(lambda: calls)
        self.assertEqual(calls[0][1], "standard")
        view._btn_scan_all.click()
        await until(lambda: len(calls) >= 3)

    async def test_connections_filter_and_untrusted_toggle(self):
        from maze.protection.process_map import Connection
        view = await self.page("conn_map")
        view.update_connections([
            Connection(1, "firefox", "10.0.0.2:5000", "1.1.1.1:443", "1.1.1.1", 443),
            Connection(2, "evilbin", "10.0.0.2:5001", "6.6.6.6:4444", "6.6.6.6", 4444),
        ])
        self.assertEqual(view._table.rowCount(), 2)
        view._only_unknown.setChecked(True)
        self.assertEqual(view._table.rowCount(), 1)
        self.assertEqual(view._table.item(0, 0).text(), "evilbin")
        view._only_unknown.setChecked(False)
        view._search.setText("https")
        self.assertEqual(view._table.rowCount(), 1)
        self.assertEqual(view._table.item(0, 3).text(), "HTTPS")


class ThreatsPageTests(GuiTestBase):
    async def test_block_rescan_export_and_clear(self):
        await self.emit(ThreatLevel.DANGEROUS, EventType.PORT_SCAN, "scan from 192.168.1.50",
                  src="192.168.1.50")
        view = await self.page("threats_view")
        self.assertTrue(view.select("192.168.1.50"))
        view._toggle_block()
        self.assertTrue(await until(lambda: self.fw.has("192.168.1.50")))
        out = Path(self.tmp.name) / "incident.md"
        with unittest.mock.patch.object(QFileDialog, "getSaveFileName",
                                        return_value=(str(out), "")):
            view._export()
        self.assertIn("192.168.1.50", out.read_text())
        with unittest.mock.patch.object(QMessageBox, "exec",
                                        return_value=QMessageBox.StandardButton.Yes):
            view._clear()
        self.assertEqual(view._table.rowCount(), 0)
        self.assertTrue(view._empty.label.isVisible())


class QuitSummaryTests(GuiTestBase):
    async def test_summary_counts_by_level_in_any_language(self):
        self.state.set_language("tr")
        await self.emit(ThreatLevel.DANGEROUS, message="a")
        await self.emit(ThreatLevel.SUSPICIOUS, message="b")
        counts = self.win.event_list.level_counts()
        self.assertEqual(counts[ThreatLevel.DANGEROUS], 1)
        self.assertEqual(counts[ThreatLevel.SUSPICIOUS], 1)


class DefaultsTests(unittest.TestCase):
    def test_fresh_install_is_english_and_dark(self):
        from maze.utils.config import MazeConfig
        from maze.gui.app_state import AppState
        cfg = MazeConfig(interface="lo")
        self.assertEqual((cfg.language, cfg.theme), ("en", "dark"))
        state = AppState(theme=cfg.theme, language=cfg.language)
        self.assertEqual((state.language, state.theme), ("en", "dark"))

    def test_unknown_values_fall_back_to_the_defaults(self):
        from maze.gui.app_state import AppState
        state = AppState(theme="neon", language="xx")
        self.assertEqual((state.language, state.theme), ("en", "dark"))

    def test_dark_theme_is_true_black(self):
        from maze.gui.theme import palette
        self.assertEqual(palette("dark")["bg"], "#000000")


if __name__ == "__main__":
    unittest.main()
