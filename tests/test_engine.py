"""
Engine wiring tests.

These cover the decisions the engine makes *between* modules — the parts no
single module's tests can see: whether a confirmed attacker is blocked before
we start scanning them, and whether an unfamiliar device on this network turns
into an alert. No sniffing, no firewall, no network: the helper, firewall and
recon are all stubbed.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core.events import Event, EventType, ThreatLevel   # noqa: E402


def run(coro):
    return asyncio.run(coro)


class _Cfg:
    interface = "test0"
    port_scan_threshold = 25
    whitelist_ips: list = []
    known_processes: list = []
    auto_block = True
    profile = "home"


class EngineTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_env = os.environ.get("MAZE_DATA_DIR")
        os.environ["MAZE_DATA_DIR"] = self._tmp.name

        from maze.core.engine import MazeEngine
        self.engine = MazeEngine(_Cfg())
        self.events: list[Event] = []

        async def collect(event):
            self.events.append(event)

        self.engine.bus.subscribe_all(collect)

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("MAZE_DATA_DIR", None)
        else:
            os.environ["MAZE_DATA_DIR"] = self._old_env
        self._tmp.cleanup()

    def _of_type(self, kind):
        return [e for e in self.events if e.type == kind]


class NewDeviceAlertTests(EngineTestBase):
    def _seen(self, ip="192.168.1.50", mac="aa:bb:cc:dd:ee:01"):
        return Event(type=EventType.DEVICE_FOUND, level=ThreatLevel.SAFE,
                     message="new device", data={"ip": ip, "mac": mac})

    def test_an_unfamiliar_device_on_a_known_network_raises_an_alert(self):
        self.engine.identity._network_id = "wifi:home"
        self.engine.inventory._learn_window = 0.0
        run(self.engine._on_device_found(self._seen()))
        alerts = self._of_type(EventType.DEVICE_NEW)
        self.assertEqual(len(alerts), 1)
        self.assertIn("aa:bb:cc:dd:ee:01", alerts[0].message)

    def test_a_familiar_device_is_silent(self):
        self.engine.identity._network_id = "wifi:home"
        self.engine.inventory._learn_window = 0.0
        run(self.engine._on_device_found(self._seen()))
        self.events.clear()
        run(self.engine._on_device_found(self._seen(ip="192.168.1.77")))
        self.assertEqual(self._of_type(EventType.DEVICE_NEW), [])

    def test_devices_seen_while_learning_a_new_network_are_silent(self):
        self.engine.identity._network_id = "wifi:cafe"
        self.engine.inventory._learn_window = 600.0
        run(self.engine._on_device_found(self._seen()))
        self.assertEqual(self._of_type(EventType.DEVICE_NEW), [])

    def test_nothing_is_claimed_without_a_network_identity(self):
        self.engine.identity._network_id = ""
        run(self.engine._on_device_found(self._seen()))
        self.assertEqual(self._of_type(EventType.DEVICE_NEW), [])

    def test_a_new_device_never_becomes_an_attacker_dossier(self):
        """It is an observation, not an accusation."""
        self.engine.identity._network_id = "wifi:home"
        self.engine.inventory._learn_window = 0.0
        run(self.engine._on_device_found(self._seen()))
        for event in list(self.events):
            self.engine.incidents.record(event)
        self.assertIsNone(self.engine.incidents.get("192.168.1.50"))


class BlockOrderingTests(EngineTestBase):
    """The block must land before the sweep, not after it.

    Blocking used to wait for reconnaissance to finish, which is time-boxed in
    tens of seconds — long enough for a scan to complete unimpeded. Measured
    against a real nmap run, the old order let 9 ports answer; the new one, 3.
    """

    @contextmanager
    def _patched(self, order, infra=()):
        async def fake_block(_engine, ip):
            order.append("block")
            return True

        async def fake_recon(ip, **kw):
            order.append("recon")
            from maze.utils.recon import ReconResult
            return ReconResult(ip=ip)

        with unittest.mock.patch.object(type(self.engine), "block_ip", fake_block), \
             unittest.mock.patch("maze.utils.recon.recon_ip", fake_recon), \
             unittest.mock.patch.object(type(self.engine), "_infra_ips",
                                        lambda _engine: set(infra)):
            yield

    def test_the_block_lands_before_the_scan(self):
        order: list[str] = []
        with self._patched(order):
            run(self.engine._do_recon("192.168.1.50", auto_block=True,
                                      trigger="port_scan"))
        self.assertEqual(order[:2], ["block", "recon"])

    def test_the_block_event_names_the_trigger_not_the_scan(self):
        order: list[str] = []
        with self._patched(order):
            run(self.engine._do_recon("192.168.1.50", auto_block=True,
                                      trigger="port_scan"))
        blocked = self._of_type(EventType.IP_BLOCKED)
        self.assertEqual(len(blocked), 1)
        self.assertIn("port scan", blocked[0].message)

    def test_a_public_source_is_neither_blocked_nor_scanned(self):
        """Source addresses are spoofable; acting on a public one would attack
        an uninvolved third party on command."""
        order: list[str] = []
        with self._patched(order):
            run(self.engine._do_recon("8.8.8.8", auto_block=True,
                                      trigger="port_scan"))
        self.assertEqual(order, [])

    def test_infrastructure_is_never_blocked(self):
        order: list[str] = []
        with self._patched(order, infra=["192.168.1.1"]):
            run(self.engine._do_recon("192.168.1.1", auto_block=True,
                                      trigger="arp_spoof"))
        self.assertEqual(order, [])

    def test_without_auto_block_only_the_scan_runs(self):
        order: list[str] = []
        with self._patched(order):
            run(self.engine._do_recon("192.168.1.50", auto_block=False))
        self.assertEqual(order, ["recon"])

    def test_recon_enriches_the_inventory_by_mac(self):
        self.engine.identity._network_id = "wifi:home"
        self.engine.inventory._learn_window = 0.0
        self.engine.inventory.observe("aa:bb:cc:dd:ee:01", "192.168.1.50",
                                      "wifi:home")

        async def fake_recon(ip, **kw):
            from maze.utils.recon import ReconResult
            r = ReconResult(ip=ip, mac="aa:bb:cc:dd:ee:01", vendor="Raspberry Pi",
                            hostname="pi.local")
            r.device_kind = "Server / workstation"
            return r

        with unittest.mock.patch("maze.utils.recon.recon_ip", fake_recon), \
             unittest.mock.patch.object(type(self.engine), "_infra_ips",
                                        lambda _engine: set()):
            run(self.engine._do_recon("192.168.1.50"))

        rec = self.engine.inventory.get("aa:bb:cc:dd:ee:01", "wifi:home")
        self.assertEqual(rec.vendor, "Raspberry Pi")
        self.assertEqual(rec.kind, "Server / workstation")
        self.assertEqual(rec.name, "pi.local")


class MacBlockingTests(EngineTestBase):
    """Blocking a lease is not blocking a device."""

    def setUp(self):
        super().setUp()
        from tests.test_core import StubHelper
        self.helper = StubHelper()
        self.engine.helper = self.helper
        self.engine.identity._network_id = "wifi:home"
        self.engine.inventory._learn_window = 0.0
        self.engine.inventory.observe("aa:bb:cc:dd:ee:01", "192.168.1.50",
                                      "wifi:home")

    def _rules(self, flag):
        return [c[c.index(flag) + 1] for c in self.helper.calls if flag in c]

    def test_blocking_an_address_also_blocks_the_device(self):
        self.assertTrue(run(self.engine.block_ip("192.168.1.50")))
        added = self._rules("--add-rich-rule")
        self.assertTrue(any("source address=192.168.1.50" in r for r in added))
        self.assertTrue(any("source mac=aa:bb:cc:dd:ee:01" in r for r in added))

    def test_unblocking_removes_the_hardware_rule_too(self):
        run(self.engine.block_ip("192.168.1.50"))
        self.helper.calls.clear()
        run(self.engine.unblock_ip("192.168.1.50"))
        removed = self._rules("--remove-rich-rule")
        self.assertTrue(any("source address=192.168.1.50" in r for r in removed))
        self.assertTrue(any("source mac=aa:bb:cc:dd:ee:01" in r for r in removed))

    def test_the_setting_can_turn_hardware_blocking_off(self):
        self.engine.cfg.block_by_mac = False
        run(self.engine.block_ip("192.168.1.50"))
        added = self._rules("--add-rich-rule")
        self.assertFalse(any("source mac=" in r for r in added))

    def test_an_unknown_device_is_still_blocked_by_address(self):
        self.assertTrue(run(self.engine.block_ip("192.168.1.99")))
        added = self._rules("--add-rich-rule")
        self.assertTrue(any("source address=192.168.1.99" in r for r in added))
        self.assertFalse(any("source mac=" in r for r in added))

    def test_the_hardware_block_is_recorded_in_the_dossier(self):
        self.engine.incidents.record(Event(
            type=EventType.PORT_SCAN, level=ThreatLevel.DANGEROUS,
            message="scan", data={"src": "192.168.1.50", "ports": [22],
                                  "technique": "syn_scan"}))
        run(self.engine.block_ip("192.168.1.50"))
        actions = " ".join(a["what"] for a in
                           self.engine.incidents.get("192.168.1.50").actions)
        self.assertIn("aa:bb:cc:dd:ee:01", actions)


class BlockEvidenceTests(EngineTestBase):
    """A dossier that stops at "blocked" omits the informative part."""

    LINE = ("2026-08-22T23:23:27+0300 msi kernel: MAZE-BLOCKIN=enp42s0 OUT= "
            "MAC=aa SRC=192.168.1.50 DST=192.168.1.42 LEN=44 PROTO=TCP "
            "SPT=51000 DPT=1720 SYN URGP=0")
    LATER = LINE.replace("23:23:27", "23:24:30").replace("DPT=1720", "DPT=445")

    def _file_attacker(self):
        self.engine.incidents.record(Event(
            type=EventType.PORT_SCAN, level=ThreatLevel.DANGEROUS,
            message="scan", data={"src": "192.168.1.50", "ports": [22],
                                  "technique": "syn_scan"}))
        self.engine.incidents.mark_blocked("192.168.1.50")

    def _journal(self, *lines):
        from maze.protection import block_log
        return unittest.mock.patch.object(
            block_log, "read_sync",
            lambda since="-1h", limit=20000, after=None:
                block_log.parse(list(lines), after=after))

    def test_drop_rule_hits_land_in_the_dossier(self):
        self._file_attacker()
        with self._journal(self.LINE):
            self.assertEqual(run(self.engine.collect_block_evidence()), 1)
        pb = self.engine.incidents.get("192.168.1.50").post_block
        self.assertEqual(pb["packets"], 1)
        self.assertEqual(pb["ports"], [1720])

    def test_counts_accumulate_across_polls_without_double_counting(self):
        self._file_attacker()
        with self._journal(self.LINE):
            run(self.engine.collect_block_evidence())
        with self._journal(self.LINE, self.LATER):   # window overlaps
            run(self.engine.collect_block_evidence())
        pb = self.engine.incidents.get("192.168.1.50").post_block
        self.assertEqual(pb["packets"], 2)
        self.assertEqual(pb["ports"], [445, 1720])

    def test_evidence_about_an_untracked_host_creates_nothing(self):
        with self._journal(self.LINE):
            self.assertEqual(run(self.engine.collect_block_evidence()), 0)
        self.assertIsNone(self.engine.incidents.get("192.168.1.50"))


class SelfTestCoverageTests(EngineTestBase):
    """Every protection must be able to prove itself.

    A module that can only report what it believes about itself is the failure
    mode this application exists to avoid — an interface saying "Active" over a
    protection that is doing nothing.
    """

    def test_every_module_can_be_verified(self):
        """The firewall is verified by the engine rather than by the module
        (it answers for the daemon and the shield, which are not modules), so
        it is exempt here and covered by the tests below."""
        missing = [name for name, mod in self.engine._modules.items()
                   if not hasattr(mod, "verify") and name != "firewall"]
        self.assertEqual(missing, [])

    def test_the_firewall_verifier_is_reachable_for_both_keys(self):
        from maze.core.verify import NA
        for key in ("fw_backend", "firewall"):
            verdict = run(self.engine.verify_module(key))
            self.assertNotEqual(verdict.status, NA, key)

    def test_a_stopped_backend_is_reported_as_a_failure(self):
        from tests.test_core import StubHelper
        from maze.core.verify import FAIL
        self.engine.helper = StubHelper(running=False)
        verdict = run(self.engine.verify_module("fw_backend"))
        self.assertEqual(verdict.status, FAIL)
        self.assertIn("not running", verdict.summary)

    def test_hardware_blocks_are_counted_in_the_verdict(self):
        """A rule form the self-test cannot see is a rule nobody audits."""
        from tests.test_core import StubHelper
        helper = StubHelper(running=True, zone="home")
        helper.blocked_ips = ["192.168.1.50"]
        helper.blocked_macs = ["aa:bb:cc:dd:ee:01"]
        self.engine.helper = helper
        verdict = run(self.engine.verify_module("fw_backend"))
        self.assertIn("1 blocked devices", verdict.summary + " ".join(verdict.evidence))


class ConfigMigrationTests(unittest.TestCase):
    """An upgrade must not look like a fresh install."""

    def test_an_existing_config_is_not_treated_as_a_first_run(self):
        import json
        from maze.utils import config as config_mod

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"interface": "wlan0", "theme": "dark"}))
            with unittest.mock.patch.object(config_mod, "CONFIG_PATH", path):
                cfg = config_mod.load_config()
        self.assertTrue(cfg.first_run_done)

    def test_a_fresh_install_asks(self):
        from maze.utils import config as config_mod
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"        # never written
            with unittest.mock.patch.object(config_mod, "CONFIG_PATH", path):
                cfg = config_mod.load_config()
        self.assertFalse(cfg.first_run_done)

    def test_an_answered_wizard_stays_answered(self):
        import json
        from maze.utils import config as config_mod
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"first_run_done": False}))
            with unittest.mock.patch.object(config_mod, "CONFIG_PATH", path):
                cfg = config_mod.load_config()
        self.assertFalse(cfg.first_run_done)


if __name__ == "__main__":
    unittest.main()
