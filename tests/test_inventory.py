"""
Unit tests for the per-network device baseline.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core.inventory import DeviceInventory, DeviceRecord   # noqa: E402

HOME = "wifi:home"
CAFE = "wifi:cafe"
PHONE = "aa:bb:cc:dd:ee:01"
LAPTOP = "aa:bb:cc:dd:ee:02"


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        # learn_window=0 → the network is already known, so sightings are news
        self.inv = DeviceInventory(data_dir=Path(self._tmp.name), learn_window=0.0)

    def tearDown(self):
        self._tmp.cleanup()

    def _learning(self, window=60.0):
        return DeviceInventory(data_dir=Path(self._tmp.name),
                               learn_window=window)

    # ── the core question ────────────────────────────────────────────────

    def test_a_device_never_seen_on_this_network_is_news(self):
        _, is_new = self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.assertTrue(is_new)

    def test_seeing_it_again_is_not(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        _, is_new = self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.assertFalse(is_new)

    def test_a_new_lease_for_a_known_device_is_not_news(self):
        """The whole point of keying on MAC: DHCP moving a device to another
        address must not look like a stranger arriving."""
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        rec, is_new = self.inv.observe(PHONE, "192.168.1.77", HOME)
        self.assertFalse(is_new)
        self.assertEqual(rec.ip, "192.168.1.77")
        self.assertIn("192.168.1.5", rec.ips)

    def test_a_device_known_at_home_is_still_a_stranger_elsewhere(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        _, is_new = self.inv.observe(PHONE, "10.0.0.9", CAFE)
        self.assertTrue(is_new)

    def test_nothing_is_recorded_without_a_network_identity(self):
        rec, is_new = self.inv.observe(PHONE, "192.168.1.5", "")
        self.assertIsNone(rec)
        self.assertFalse(is_new)

    # ── the learning window ──────────────────────────────────────────────

    def test_devices_found_while_learning_become_the_baseline(self):
        inv = self._learning()
        rec, is_new = inv.observe(PHONE, "192.168.1.5", HOME)
        self.assertFalse(is_new)
        self.assertTrue(rec.trusted)
        self.assertTrue(inv.is_learning(HOME))

    def test_after_the_window_closes_arrivals_are_news(self):
        inv = self._learning(window=0.05)
        inv.observe(PHONE, "192.168.1.5", HOME)
        time.sleep(0.06)
        _, is_new = inv.observe(LAPTOP, "192.168.1.6", HOME)
        self.assertTrue(is_new)
        self.assertFalse(inv.is_learning(HOME))

    def test_a_known_network_is_not_re_learned_after_a_restart(self):
        inv = self._learning(window=600.0)
        inv.observe(PHONE, "192.168.1.5", HOME)   # baseline
        inv.save()

        reopened = DeviceInventory(data_dir=Path(self._tmp.name),
                                   learn_window=600.0)
        self.assertFalse(reopened.is_learning(HOME))
        _, is_new = reopened.observe(LAPTOP, "192.168.1.6", HOME)
        self.assertTrue(is_new)

    # ── user decisions ───────────────────────────────────────────────────

    def test_a_name_follows_the_device_to_other_networks(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.inv.set_label(PHONE, HOME, "Berk's phone")
        rec, _ = self.inv.observe(PHONE, "10.0.0.9", CAFE)
        self.assertEqual(rec.label, "Berk's phone")
        self.assertEqual(rec.display_name, "Berk's phone")

    def test_trust_is_per_network(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.inv.observe(PHONE, "10.0.0.9", CAFE)
        self.inv.set_trusted(PHONE, HOME, True)
        self.assertTrue(self.inv.get(PHONE, HOME).trusted)
        self.assertFalse(self.inv.get(PHONE, CAFE).trusted)

    def test_unknown_lists_only_the_unvouched(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.inv.observe(LAPTOP, "192.168.1.6", HOME)
        self.inv.set_trusted(PHONE, HOME, True)
        self.assertEqual([r.mac for r in self.inv.unknown(HOME)], [LAPTOP])

    def test_forgetting_a_network_starts_it_over(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.inv.forget_network(HOME)
        self.assertEqual(self.inv.all(HOME), [])

    # ── enrichment ───────────────────────────────────────────────────────

    def test_recon_results_are_folded_in_and_never_blanked(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.inv.enrich(PHONE, HOME, vendor="Apple", kind="Mobile device",
                        name="berk-iphone")
        self.inv.enrich(PHONE, HOME, vendor="", kind="", name="")
        rec = self.inv.get(PHONE, HOME)
        self.assertEqual(rec.vendor, "Apple")
        self.assertEqual(rec.kind, "Mobile device")
        self.assertEqual(rec.name, "berk-iphone")

    def test_randomised_macs_are_flagged(self):
        rec, _ = self.inv.observe("da:38:63:d3:27:c6", "192.168.1.9", HOME)
        self.assertTrue(rec.randomized_mac)
        rec, _ = self.inv.observe("b8:27:eb:11:22:33", "192.168.1.10", HOME)
        self.assertFalse(rec.randomized_mac)

    def test_macs_are_matched_case_insensitively(self):
        self.inv.observe(PHONE.upper(), "192.168.1.5", HOME)
        _, is_new = self.inv.observe(PHONE.lower(), "192.168.1.5", HOME)
        self.assertFalse(is_new)

    # ── persistence ──────────────────────────────────────────────────────

    def test_the_baseline_survives_a_restart(self):
        self.inv.observe(PHONE, "192.168.1.5", HOME)
        self.inv.set_label(PHONE, HOME, "phone")
        self.inv.set_trusted(PHONE, HOME, True)

        reopened = DeviceInventory(data_dir=Path(self._tmp.name),
                                   learn_window=0.0)
        rec = reopened.get(PHONE, HOME)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.label, "phone")
        self.assertTrue(rec.trusted)
        _, is_new = reopened.observe(PHONE, "192.168.1.5", HOME)
        self.assertFalse(is_new)

    def test_a_corrupt_file_does_not_stop_the_app(self):
        (Path(self._tmp.name) / "devices.json").write_text("{ not json")
        inv = DeviceInventory(data_dir=Path(self._tmp.name), learn_window=0.0)
        self.assertEqual(inv.all(), [])

    def test_named_devices_are_never_evicted(self):
        from maze.core import inventory as mod
        original = mod._MAX_DEVICES_PER_NETWORK
        mod._MAX_DEVICES_PER_NETWORK = 3
        try:
            self.inv.observe(PHONE, "192.168.1.5", HOME)
            self.inv.set_label(PHONE, HOME, "keep me")
            for i in range(10):
                self.inv.observe(f"aa:bb:cc:00:00:{i:02x}", f"192.168.1.{i}", HOME)
            self.assertIsNotNone(self.inv.get(PHONE, HOME))
        finally:
            mod._MAX_DEVICES_PER_NETWORK = original


class RecordTests(unittest.TestCase):
    def test_display_name_prefers_the_users_name(self):
        rec = DeviceRecord(mac=PHONE, network_id=HOME, vendor="Apple",
                           name="iphone", label="Berk's phone")
        self.assertEqual(rec.display_name, "Berk's phone")
        rec.label = ""
        self.assertEqual(rec.display_name, "iphone")
        rec.name = ""
        self.assertEqual(rec.display_name, "Apple")
        rec.vendor = ""
        self.assertEqual(rec.display_name, PHONE)

    def test_round_trips_through_json(self):
        rec = DeviceRecord(mac=PHONE, network_id=HOME, label="x", trusted=True,
                           ips=["192.168.1.5"], times_seen=4,
                           first_seen=datetime.now() - timedelta(days=2))
        back = DeviceRecord.from_dict(rec.to_dict())
        self.assertEqual(back.mac, rec.mac)
        self.assertEqual(back.label, "x")
        self.assertTrue(back.trusted)
        self.assertEqual(back.times_seen, 4)
        self.assertEqual(back.first_seen.date(), rec.first_seen.date())


if __name__ == "__main__":
    unittest.main()
