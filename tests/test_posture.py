"""
Tests for the suite-posture snapshot attached to every incident.

The point of posture.py is to answer "was I covered when this happened", so
the tests care most about the difference between *false* and *unknown*: an
incident report that says "DNS was in the clear" when Entropy Shield was never
installed is worse than one that says nothing, because a user can act on it.

Everything here is hermetic — the module's paths are redirected into a temp
directory, because the developer machine runs the very apps being probed and
an early version of these tests passed only there.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import json
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core import posture                              # noqa: E402
from maze.core.events import Event, EventType, ThreatLevel  # noqa: E402
from maze.core.incident import Attacker, IncidentStore      # noqa: E402


class PostureTestCase(unittest.TestCase):
    """Redirects every path posture.py reads into a scratch directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.status = root / "status"
        self.cloak = root / "cloak" / "state.json"
        self.entropy = root / "entropy"
        self.status.mkdir(parents=True)
        self.cloak.parent.mkdir(parents=True)

        self._patches = [
            unittest.mock.patch.object(posture, "STATUS_DIR", self.status),
            unittest.mock.patch.object(posture, "CLOAK_STATE", self.cloak),
            unittest.mock.patch.object(posture, "ENTROPY_RUN", self.entropy),
            unittest.mock.patch.object(posture, "DNSCRYPT_DROPIN",
                                       root / "resolved" / "entropy-shield.conf"),
            # The fallback asks PATH whether the app exists at all.
            unittest.mock.patch.object(posture.shutil, "which",
                                       return_value=None),
        ]
        for p in self._patches:
            p.start()
        posture._cache = None

    def tearDown(self):
        for p in self._patches:
            p.stop()
        posture._cache = None
        self._tmp.cleanup()

    def write_cloak(self, **kw):
        self.cloak.write_text(json.dumps(kw))

    def write_status(self, app, **kw):
        (self.status / f"{app}.json").write_text(json.dumps(kw))


class TestUnknownIsNotFalse(PostureTestCase):

    def test_nothing_installed_reports_unknown(self):
        snap = posture.capture(force=True)
        self.assertIsNone(snap["mac_randomised"])
        self.assertIsNone(snap["dns_encrypted"])
        self.assertIsNone(snap["tor_proxy"])

    def test_unknown_values_make_no_claims(self):
        snap = posture.capture(force=True)
        self.assertEqual(posture.describe(snap), [])

    def test_absent_app_is_unknown_but_present_app_is_false(self):
        self.assertIsNone(posture.capture(force=True)["dns_encrypted"])
        self.entropy.mkdir(parents=True)          # app is here, DNS is not on
        self.assertFalse(posture.capture(force=True)["dns_encrypted"])


class TestCloakState(PostureTestCase):

    def test_rotated_mac_is_randomised(self):
        self.write_cloak(running=True, paused="", interfaces={
            "wlan0": {"mac": "aa:bb:cc:00:11:22",
                      "original": "11:22:33:44:55:66", "rotations": 3}})
        snap = posture.capture(force=True)
        self.assertTrue(snap["mac_randomised"])
        self.assertIn("MAC address randomised", posture.describe(snap))

    def test_paused_by_vpn_is_not_randomised(self):
        self.write_cloak(running=True, paused="vpn", interfaces={
            "wlan0": {"mac": "11:22:33:44:55:66",
                      "original": "11:22:33:44:55:66", "rotations": 0}})
        snap = posture.capture(force=True)
        self.assertFalse(snap["mac_randomised"])
        self.assertIn("MAC address was the hardware one",
                      posture.describe(snap))

    def test_daemon_not_running_is_not_randomised(self):
        self.write_cloak(running=False, interfaces={})
        self.assertFalse(posture.capture(force=True)["mac_randomised"])

    def test_corrupt_state_file_does_not_raise(self):
        self.cloak.write_text("{ not json")
        self.assertIsNone(posture.capture(force=True)["mac_randomised"])


class TestStatusContract(PostureTestCase):
    """A published status file wins over sniffing the app's own artefacts."""

    def test_contract_overrides_fallback(self):
        self.write_cloak(running=False, interfaces={})       # fallback says no
        self.write_status("maze-cloak", mac_randomised=True)  # contract says yes
        self.assertTrue(posture.capture(force=True)["mac_randomised"])

    def test_contract_supplies_scan_age(self):
        self.write_status("qlam", last_scan=time.time() - 3 * 86400)
        snap = posture.capture(force=True)
        self.assertTrue(any("3 day" in line for line in posture.describe(snap)))

    def test_corrupt_contract_falls_back(self):
        (self.status / "maze-cloak.json").write_text("{ not json")
        self.write_cloak(running=True, paused="", interfaces={
            "wlan0": {"mac": "aa:bb", "original": "cc:dd", "rotations": 1}})
        self.assertTrue(posture.capture(force=True)["mac_randomised"])


class TestIncidentIntegration(PostureTestCase):

    def _record(self, ip="192.168.1.66"):
        store = IncidentStore(data_dir=Path(self._tmp.name) / "mg",
                              autosave=False)
        return store, store.record(Event(
            type=EventType.ARP_SPOOF, level=ThreatLevel.DANGEROUS,
            message="ARP spoof", data={"ip": "192.168.1.1", "src": ip,
                                       "mac": "de:ad:be:ef:00:01"}))

    def test_dossier_captures_posture(self):
        self.write_status("maze-cloak", mac_randomised=True)
        posture._cache = None
        _, att = self._record()
        self.assertTrue(att.posture["mac_randomised"])

    def test_posture_survives_a_save_load_round_trip(self):
        self.write_status("maze-cloak", mac_randomised=True)
        posture._cache = None
        _, att = self._record()
        self.assertTrue(Attacker.from_dict(att.to_dict())
                        .posture["mac_randomised"])

    def test_report_states_the_defences(self):
        self.write_status("maze-cloak", mac_randomised=True)
        posture._cache = None
        _, att = self._record()
        report = att.report()
        self.assertIn("## Your defences at the time", report)
        self.assertIn("MAC address randomised", report)

    def test_posture_failure_never_costs_us_the_attack(self):
        """Filing the attack matters more than knowing the posture."""
        with unittest.mock.patch.object(posture, "capture",
                                        side_effect=RuntimeError("boom")):
            _, att = self._record(ip="10.0.0.5")
        self.assertIsNotNone(att)
        self.assertEqual(att.ip, "10.0.0.5")
        self.assertEqual(att.posture, {})


if __name__ == "__main__":
    unittest.main()
