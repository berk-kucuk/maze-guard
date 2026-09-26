"""
Unit tests for on-demand device intelligence and its cache lifetime.

No network and no Qt: recon_ip is stubbed, so these exercise the caching and
invalidation rules — the part that decides whether an answer is still true.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import asyncio
import re
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core.device_intel import (            # noqa: E402
    DeviceIntel, DeviceIntelCache, describe_progress, export_markdown,
    format_intel, summarize_intel,
)


def run(coro):
    return asyncio.run(coro)


class _FakeResult:
    """Stands in for maze.utils.recon.ReconResult."""

    def __init__(self, ip, mac="aa:bb:cc:dd:ee:ff"):
        self.ip = ip
        self.mac = mac
        self.calls = 0

    def to_dict(self):
        return {
            "ip": self.ip, "mac": self.mac, "vendor": "Raspberry Pi",
            "hostname": "pi.local", "netbios_name": "", "mdns_name": "",
            "open_ports": [[22, "SSH"], [80, "HTTP"]],
            "banners": {"22": "OpenSSH_9.6"}, "http_titles": {},
            "os_hint": "Linux", "tls_info": {}, "latency_ms": 3.2,
            "randomized_mac": False, "risk_score": 15, "findings": [],
        }


def _patch_recon(counter=None, result=None, exc=None, profiles=None,
                 progress=None):
    """Patch maze.utils.recon.recon_ip; returns the mock."""
    async def fake(ip, port_timeout=None, profile="standard", on_progress=None):
        if counter is not None:
            counter.append(ip)
        if profiles is not None:
            profiles.append(profile)
        if on_progress and progress:
            for tick in progress:
                on_progress(*tick)
        if exc is not None:
            raise exc
        return result or _FakeResult(ip)
    return unittest.mock.patch("maze.utils.recon.recon_ip", fake)


def _cache(ttl=900.0, net="wifi:home", incidents=None, inventory=None):
    c = DeviceIntelCache("wlan0", ttl=ttl, incidents=incidents,
                         inventory=inventory)
    c._identity._network_id = net
    return c


class DeviceIntelCacheTests(unittest.TestCase):
    def test_gather_caches_and_does_not_rescan(self):
        seen = []
        c = _cache()
        with _patch_recon(seen), unittest.mock.patch.object(
                DeviceIntelCache, "refresh_network",
                unittest.mock.AsyncMock(return_value="wifi:home")):
            first = run(c.gather("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
            second = run(c.gather("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
        self.assertEqual(seen, ["192.168.1.10"])
        self.assertIs(first, second)
        self.assertEqual(first.vendor, "Raspberry Pi")
        self.assertEqual(len(first.open_ports), 2)

    def test_force_rescans(self):
        seen = []
        c = _cache()
        with _patch_recon(seen), unittest.mock.patch.object(
                DeviceIntelCache, "refresh_network",
                unittest.mock.AsyncMock(return_value="wifi:home")):
            run(c.gather("192.168.1.10"))
            run(c.gather("192.168.1.10", force=True))
        self.assertEqual(len(seen), 2)

    def test_public_ip_is_never_probed(self):
        seen = []
        c = _cache()
        with _patch_recon(seen):
            intel = run(c.gather("8.8.8.8"))
        self.assertEqual(seen, [])
        self.assertEqual(intel.error, "not_local")
        self.assertIsNone(c.get("8.8.8.8"))

    def test_failed_scan_is_not_cached(self):
        c = _cache()
        with _patch_recon(exc=OSError("boom")), unittest.mock.patch.object(
                DeviceIntelCache, "refresh_network",
                unittest.mock.AsyncMock(return_value="wifi:home")):
            intel = run(c.gather("192.168.1.10"))
        self.assertTrue(intel.error)
        self.assertIsNone(c.get("192.168.1.10"))

    def test_entry_expires_with_ttl(self):
        c = _cache(ttl=60.0)
        intel = DeviceIntel(ip="192.168.1.10", network_id="wifi:home")
        c._entries["192.168.1.10"] = intel
        self.assertIsNotNone(c.get("192.168.1.10"))

        intel.gathered_at -= 61.0
        self.assertIsNone(c.get("192.168.1.10"))
        self.assertNotIn("192.168.1.10", c._entries)

    def test_prune_drops_only_expired(self):
        c = _cache(ttl=60.0)
        fresh = DeviceIntel(ip="192.168.1.10", network_id="wifi:home")
        old = DeviceIntel(ip="192.168.1.11", network_id="wifi:home")
        old.gathered_at -= 120.0
        c._entries = {"192.168.1.10": fresh, "192.168.1.11": old}
        self.assertEqual(c.prune(), 1)
        self.assertEqual(list(c._entries), ["192.168.1.10"])

    def test_mac_change_invalidates_the_lease(self):
        c = _cache()
        c._entries["192.168.1.10"] = DeviceIntel(
            ip="192.168.1.10", arp_mac="aa:bb:cc:dd:ee:ff",
            network_id="wifi:home")
        self.assertIsNotNone(c.get("192.168.1.10", "AA:BB:CC:DD:EE:FF"))
        self.assertIsNone(c.get("192.168.1.10", "11:22:33:44:55:66"))
        self.assertNotIn("192.168.1.10", c._entries)

    def test_joining_a_different_network_drops_everything(self):
        c = _cache()
        c._entries["192.168.1.10"] = DeviceIntel(
            ip="192.168.1.10", network_id="wifi:home")
        with unittest.mock.patch(
                "maze.network.identity.current_network_id",
                return_value="wifi:cafe"):
            run(c.refresh_network())
        self.assertEqual(c.network_id, "wifi:cafe")
        self.assertEqual(c._entries, {})

    def test_same_network_keeps_entries(self):
        c = _cache()
        c._entries["192.168.1.10"] = DeviceIntel(
            ip="192.168.1.10", network_id="wifi:home")
        with unittest.mock.patch(
                "maze.network.identity.current_network_id",
                return_value="wifi:home"):
            run(c.refresh_network())
        self.assertIn("192.168.1.10", c._entries)

    def test_unreadable_network_id_is_not_treated_as_a_change(self):
        c = _cache()
        c._entries["192.168.1.10"] = DeviceIntel(
            ip="192.168.1.10", network_id="wifi:home")
        with unittest.mock.patch(
                "maze.network.identity.current_network_id", return_value=""):
            run(c.refresh_network())
        self.assertEqual(c.network_id, "wifi:home")
        self.assertIn("192.168.1.10", c._entries)

    def test_entry_from_another_network_is_rejected(self):
        c = _cache(net="wifi:cafe")
        c._entries["192.168.1.10"] = DeviceIntel(
            ip="192.168.1.10", network_id="wifi:home")
        self.assertIsNone(c.get("192.168.1.10"))

    def test_switching_interface_clears(self):
        c = _cache()
        c._entries["192.168.1.10"] = DeviceIntel(ip="192.168.1.10")
        c.set_interface("eth0")
        self.assertEqual(c._entries, {})
        c._entries["192.168.1.10"] = DeviceIntel(ip="192.168.1.10")
        c.set_interface("eth0")          # unchanged — must not clear
        self.assertIn("192.168.1.10", c._entries)

    def test_concurrent_gathers_share_one_scan(self):
        seen = []

        async def scenario():
            c = _cache()
            with _patch_recon(seen), unittest.mock.patch.object(
                    DeviceIntelCache, "refresh_network",
                    unittest.mock.AsyncMock(return_value="wifi:home")):
                a, b = await asyncio.gather(
                    c.gather("192.168.1.10"), c.gather("192.168.1.10"))
            self.assertIs(a, b)
            self.assertFalse(c.is_scanning("192.168.1.10"))

        run(scenario())
        self.assertEqual(len(seen), 1)

    def test_existing_incident_is_enriched_but_none_is_created(self):
        store = unittest.mock.MagicMock()
        store.get.return_value = None
        c = _cache(incidents=store)
        with _patch_recon(), unittest.mock.patch.object(
                DeviceIntelCache, "refresh_network",
                unittest.mock.AsyncMock(return_value="wifi:home")):
            run(c.gather("192.168.1.10"))
        store.attach_recon.assert_not_called()

        store.get.return_value = object()
        with _patch_recon(), unittest.mock.patch.object(
                DeviceIntelCache, "refresh_network",
                unittest.mock.AsyncMock(return_value="wifi:home")):
            run(c.gather("192.168.1.10", force=True))
        store.attach_recon.assert_called_once()


class ScanDepthTests(unittest.TestCase):
    def _no_network(self):
        return unittest.mock.patch.object(
            DeviceIntelCache, "refresh_network",
            unittest.mock.AsyncMock(return_value="wifi:home"))

    def test_the_requested_profile_reaches_the_scanner(self):
        profiles = []
        c = _cache()
        with _patch_recon(profiles=profiles), self._no_network():
            run(c.gather("192.168.1.10", profile="thorough"))
        self.assertEqual(profiles, ["thorough"])
        self.assertEqual(c.get("192.168.1.10").profile, "thorough")

    def test_a_deeper_scan_is_not_satisfied_by_a_shallow_cache_entry(self):
        profiles = []
        c = _cache()
        with _patch_recon(profiles=profiles), self._no_network():
            run(c.gather("192.168.1.10", profile="quick"))
            run(c.gather("192.168.1.10", profile="thorough"))
        self.assertEqual(profiles, ["quick", "thorough"])

    def test_a_shallower_scan_reuses_the_deeper_answer(self):
        profiles = []
        c = _cache()
        with _patch_recon(profiles=profiles), self._no_network():
            run(c.gather("192.168.1.10", profile="thorough"))
            run(c.gather("192.168.1.10", profile="quick"))
        self.assertEqual(profiles, ["thorough"])

    def test_the_gateway_is_labelled_from_the_routing_table(self):
        """Port shape guesses at what a device is; the routing table knows
        which one is the router."""
        c = _cache()
        c._identity._gateway = "192.168.1.1"
        with _patch_recon(), self._no_network():
            intel = run(c.gather("192.168.1.1"))
        self.assertEqual(intel.device_kind, "Router / gateway")
        self.assertTrue(intel.result["is_gateway"])

    def test_other_hosts_keep_their_classification(self):
        c = _cache()
        c._identity._gateway = "192.168.1.1"
        with _patch_recon(), self._no_network():
            intel = run(c.gather("192.168.1.10"))
        self.assertNotEqual(intel.device_kind, "Router / gateway")

    def test_progress_is_exposed_while_scanning_and_cleared_after(self):
        c = _cache()
        seen = {}

        async def scenario():
            async def fake(ip, port_timeout=None, profile="standard",
                           on_progress=None):
                on_progress("ports", 12, 93)
                seen["during"] = c.progress(ip)
                return _FakeResult(ip)

            with unittest.mock.patch("maze.utils.recon.recon_ip", fake), \
                 self._no_network():
                await c.gather("192.168.1.10")

        run(scenario())
        self.assertEqual(seen["during"], ("ports", 12, 93))
        self.assertIsNone(c.progress("192.168.1.10"))

    def test_progress_descriptions_are_readable(self):
        self.assertIn("12/93", describe_progress(("ports", 12, 93)))
        self.assertEqual(describe_progress(("identity", 0, 1)),
                         "dev_stage_identity")
        self.assertEqual(describe_progress(None), "dev_scanning")


class ExportTests(unittest.TestCase):
    def _intel(self):
        data = _FakeResult("192.168.1.10").to_dict()
        data.update({"device_kind": "Printer", "ports_scanned": 93,
                     "duration_s": 4.1, "partial": True,
                     "upnp": {"manufacturer": "Brother", "model_name": "L2350",
                              "friendly_name": "Office printer"}})
        return DeviceIntel(ip="192.168.1.10", arp_mac="aa:bb:cc:dd:ee:ff",
                           result=data, profile="thorough")

    def test_report_is_self_contained(self):
        text = export_markdown(self._intel())
        for expected in ("# Maze Guard device report — 192.168.1.10",
                         "Brother L2350", "Printer", "thorough",
                         "22/SSH", "OpenSSH_9.6"):
            self.assertIn(expected, text)

    def test_an_incomplete_sweep_is_declared_in_the_report(self):
        self.assertIn("INCOMPLETE", export_markdown(self._intel()))

    def test_upnp_name_is_used_when_dns_is_silent(self):
        self.assertEqual(self._intel().name, "pi.local")   # hostname wins
        bare = DeviceIntel(ip="10.0.0.5",
                           result={"upnp": {"friendly_name": "Living Room TV"}})
        self.assertEqual(bare.name, "Living Room TV")


class FormattingTests(unittest.TestCase):
    def _intel(self):
        return DeviceIntel(ip="192.168.1.10", arp_mac="aa:bb:cc:dd:ee:ff",
                           result=_FakeResult("192.168.1.10").to_dict())

    def test_report_covers_identity_and_ports(self):
        text = format_intel(self._intel())
        self.assertIn("192.168.1.10", text)
        self.assertIn("aa:bb:cc:dd:ee:ff", text)
        self.assertIn("Raspberry Pi", text)
        self.assertIn("22/SSH", text)
        self.assertIn("OpenSSH_9.6", text)

    def test_summary_counts_ports_and_risk(self):
        self.assertIn("2", summarize_intel(self._intel()))
        self.assertIn("15", summarize_intel(self._intel()))

    def test_labels_stay_aligned_whatever_the_translation(self):
        """Turkish labels are wider than English ones; a hardcoded column
        width put the value flush against the colon in one language."""
        intel = self._intel()
        intel.result["device_kind"] = "Printer"
        text = format_intel(intel, lambda k: k.upper() * 2)
        rows = [l for l in text.splitlines()
                if re.match(r"^(IP|MAC|OS|RTT|DEV_KIND)", l)]
        self.assertGreaterEqual(len(rows), 4)
        value_columns = {re.match(r"[^:]+:\s+", l).end() for l in rows}
        self.assertEqual(len(value_columns), 1)

    def test_public_address_report_explains_itself(self):
        text = format_intel(DeviceIntel(ip="8.8.8.8", error="not_local"))
        self.assertEqual(text, "dev_not_local")


if __name__ == "__main__":
    unittest.main()
