"""
Unit tests for the reconnaissance engine.

Nothing here touches the network: the probe primitives are stubbed, so what is
under test is the sweep's behaviour (budgets, partial results, progress) and
the interpretation layer (device classification, UPnP handling).

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import asyncio
import sys
import unittest
import unittest.mock
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.utils import recon                                    # noqa: E402
from maze.utils.recon import (                                  # noqa: E402
    ReconResult, ScanProfile, SCAN_PROFILES, _classify_device, _split_url,
    format_recon, get_profile, recon_ip,
)

AsyncMock = unittest.mock.AsyncMock


def run(coro):
    return asyncio.run(coro)


@contextmanager
def stub_probes(**overrides):
    """Replace every network primitive recon_ip fans out to."""
    defaults = {
        "_reverse_dns": "",
        "_scan_ports": ([], False, 0.0),
        "_ping": ("Linux / Unix", 1.0),
        "_get_mac": "",
        "_netbios_query": "",
        "_mdns_query": "",
        "_upnp_probe": {},
    }
    defaults.update(overrides)
    patches = [unittest.mock.patch.object(recon, name,
                                          AsyncMock(return_value=value))
               for name, value in defaults.items()]
    patches.append(unittest.mock.patch.object(recon, "_fingerprint_services",
                                              AsyncMock()))
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in patches:
            p.stop()


class ScanProfileTests(unittest.TestCase):
    def test_profiles_get_wider_with_depth(self):
        quick = SCAN_PROFILES["quick"].port_count
        standard = SCAN_PROFILES["standard"].port_count
        thorough = SCAN_PROFILES["thorough"].port_count
        self.assertLess(quick, standard)
        self.assertLess(standard, thorough)

    def test_unknown_profile_falls_back_to_standard(self):
        self.assertEqual(get_profile("nonsense").name, "standard")
        self.assertEqual(get_profile("").name, "standard")

    def test_thorough_covers_the_assigned_range(self):
        ports = set(SCAN_PROFILES["thorough"].ports)
        self.assertTrue({1, 80, 443, 1024} <= ports)
        self.assertIn(4444, ports)          # the high ports still matter

    def test_recon_records_which_profile_ran(self):
        with stub_probes():
            result = run(recon_ip("192.168.1.5", profile="quick"))
        self.assertEqual(result.profile, "quick")
        self.assertEqual(result.ports_scanned, SCAN_PROFILES["quick"].port_count)

    def test_quick_profile_skips_the_deep_pass(self):
        with stub_probes():
            run(recon_ip("192.168.1.5", profile="quick"))
            recon._upnp_probe.assert_not_called()
            recon._fingerprint_services.assert_not_called()

    def test_standard_profile_runs_the_deep_pass(self):
        with stub_probes():
            run(recon_ip("192.168.1.5"))
            recon._upnp_probe.assert_called_once()
            recon._fingerprint_services.assert_called_once()


class SweepTests(unittest.TestCase):
    def _profile(self, ports, budget):
        return ScanProfile("test", tuple(ports), port_timeout=0.05,
                           budget=budget, deep=False)

    def test_a_budget_overrun_keeps_what_was_already_found(self):
        """The old sweep returned [] on timeout — indistinguishable from a
        host with nothing open, which is the one answer that must not be
        invented."""
        async def check(ip, port, timeout):
            if port == 80:
                return True
            await asyncio.sleep(5)          # never finishes inside the budget
            return False

        with unittest.mock.patch.object(recon, "_check_port", check):
            found, partial, rtt = run(recon._scan_ports(
                "192.168.1.5", 0.05, self._profile([80, 81, 82], 0.3)))
        self.assertEqual(found, [(80, "HTTP")])
        self.assertTrue(partial)

    def test_a_completed_sweep_is_not_flagged_partial(self):
        async def check(ip, port, timeout):
            return port in (22, 443)

        with unittest.mock.patch.object(recon, "_check_port", check):
            found, partial, rtt = run(recon._scan_ports(
                "192.168.1.5", 0.05, self._profile([22, 80, 443], 5.0)))
        self.assertEqual([p for p, _ in found], [22, 443])
        self.assertFalse(partial)

    def test_tcp_handshake_timing_substitutes_for_a_filtered_ping(self):
        """ICMP is routinely dropped; a host we just shook hands with must not
        be reported as 0.0 ms."""
        with stub_probes(_scan_ports=([(80, "HTTP")], False, 4.2),
                         _ping=("", 0.0)):
            result = run(recon_ip("192.168.1.5"))
        self.assertEqual(result.latency_ms, 4.2)

    def test_icmp_timing_is_preferred_when_it_answers(self):
        with stub_probes(_scan_ports=([(80, "HTTP")], False, 40.0),
                         _ping=("Linux / Unix", 1.5)):
            result = run(recon_ip("192.168.1.5"))
        self.assertEqual(result.latency_ms, 1.5)

    def test_progress_is_reported_as_probes_land(self):
        seen = []

        async def check(ip, port, timeout):
            return False

        with unittest.mock.patch.object(recon, "_check_port", check):
            run(recon._scan_ports("192.168.1.5", 0.05,
                                  self._profile(range(1, 21), 5.0),
                                  lambda *a: seen.append(a)))
        self.assertTrue(seen)
        self.assertEqual(seen[-1], ("ports", 20, 20))

    def test_recon_reports_stages_to_a_progress_callback(self):
        stages = []
        with stub_probes():
            run(recon_ip("192.168.1.5", profile="quick",
                         on_progress=lambda s, d, t: stages.append(s)))
        self.assertEqual(stages[0], "identity")
        self.assertEqual(stages[-1], "done")

    def test_a_broken_progress_callback_cannot_fail_a_scan(self):
        def explode(*_args):
            raise RuntimeError("UI is gone")

        with stub_probes():
            result = run(recon_ip("192.168.1.5", on_progress=explode))
        self.assertEqual(result.ip, "192.168.1.5")


class DeviceClassificationTests(unittest.TestCase):
    def _kind(self, ports, **fields):
        result = ReconResult(ip="192.168.1.5", **fields)
        return _classify_device(result, set(ports))

    def test_cups_alone_is_not_a_printer(self):
        """CUPS ships on every Linux desktop; calling those printers made the
        inventory worse than leaving the field blank."""
        self.assertNotEqual(self._kind([631, 22]), "Printer")

    def test_jetdirect_is_a_printer(self):
        self.assertEqual(self._kind([9100, 631]), "Printer")

    def test_rtsp_is_a_camera(self):
        self.assertEqual(self._kind([554, 80]), "IP camera")

    def test_upnp_description_names_a_router(self):
        self.assertEqual(
            self._kind([80], upnp={"model_description": "Internet Gateway Device"}),
            "Router / gateway")

    def test_adb_is_a_mobile_device(self):
        self.assertEqual(self._kind([5555]), "Mobile device")

    def test_windows_ports_are_a_workstation(self):
        self.assertEqual(self._kind([135, 445, 3389]), "Workstation / server")

    def test_nothing_recognisable_stays_blank(self):
        self.assertEqual(self._kind([]), "")


class UpnpTests(unittest.TestCase):
    def test_url_is_split_into_host_port_path(self):
        self.assertEqual(_split_url("http://192.168.1.1:5000/desc.xml"),
                         ("192.168.1.1", 5000, "/desc.xml"))
        self.assertEqual(_split_url("http://192.168.1.1/x"),
                         ("192.168.1.1", 80, "/x"))
        self.assertEqual(_split_url("garbage"), ("", 0, ""))

    def test_a_location_pointing_elsewhere_is_never_fetched(self):
        """LOCATION comes from the device. A host that answers with someone
        else's URL must not turn us into the one making that request."""
        with unittest.mock.patch.object(
                recon, "_ssdp_location",
                return_value="http://198.51.100.7:80/evil.xml"), \
             unittest.mock.patch.object(recon, "_http_get", AsyncMock()) as get:
            out = run(recon._upnp_probe("192.168.1.5"))
        self.assertEqual(out, {})
        get.assert_not_called()

    def test_description_fields_become_identity(self):
        xml = ("<root><device><friendlyName>Living Room TV</friendlyName>"
               "<manufacturer>Acme</manufacturer>"
               "<modelName>X100</modelName></device></root>")
        with unittest.mock.patch.object(
                recon, "_ssdp_location",
                return_value="http://192.168.1.5:8080/desc.xml"), \
             unittest.mock.patch.object(recon, "_http_get",
                                        AsyncMock(return_value=xml)):
            out = run(recon._upnp_probe("192.168.1.5"))
        self.assertEqual(out["friendly_name"], "Living Room TV")
        self.assertEqual(out["model_name"], "X100")

    def test_upnp_name_is_used_when_nothing_else_answers(self):
        with stub_probes(_upnp_probe={"friendly_name": "Archer C6",
                                      "manufacturer": "TP-Link"}):
            result = run(recon_ip("192.168.1.1"))
        self.assertEqual(result.name, "Archer C6")
        self.assertEqual(result.vendor, "TP-Link")

    def test_a_real_mac_vendor_outranks_the_upnp_one(self):
        with stub_probes(_get_mac="b8:27:eb:11:22:33",
                         _upnp_probe={"manufacturer": "Generic"}):
            result = run(recon_ip("192.168.1.1"))
        self.assertEqual(result.vendor, "Raspberry Pi")


class IPv6Tests(unittest.TestCase):
    """A v6 target is scanned the same way; the v4-only name services simply
    have nothing to say, and must not spend two seconds saying it."""

    def test_v4_only_name_services_answer_immediately_for_v6(self):
        with unittest.mock.patch.object(recon, "_send_netbios") as netbios, \
             unittest.mock.patch.object(recon, "_ssdp_location") as ssdp:
            self.assertEqual(run(recon._netbios_query("fe80::1")), "")
            self.assertEqual(run(recon._mdns_query("fe80::1")), "")
            self.assertEqual(run(recon._upnp_probe("fe80::1")), {})
        netbios.assert_not_called()
        ssdp.assert_not_called()

    def test_they_still_run_for_v4(self):
        with unittest.mock.patch.object(recon, "_ssdp_location",
                                        return_value="") as ssdp:
            run(recon._upnp_probe("192.168.1.5"))
        ssdp.assert_called_once()

    def test_a_v6_host_still_gets_a_dossier(self):
        with stub_probes(_scan_ports=([(22, "SSH")], False, 2.0),
                         _reverse_dns="berk-laptop"):
            result = run(recon_ip("fe80::42%wlan0", profile="quick"))
        self.assertEqual(result.hostname, "berk-laptop")
        self.assertEqual(result.open_ports, [(22, "SSH")])
        self.assertEqual(result.ip, "fe80::42%wlan0")

    def test_the_zone_index_is_stripped_before_asking_the_kernel(self):
        """`ip neigh` is already per-interface and rejects fe80::1%wlan0."""
        seen = {}

        def fake_check_output(cmd, **kw):
            seen["cmd"] = cmd
            return "fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"

        with unittest.mock.patch("subprocess.check_output", fake_check_output):
            mac = run(recon._get_mac("fe80::1%wlan0"))
        self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")
        self.assertNotIn("%", " ".join(seen["cmd"]))


class FormatTests(unittest.TestCase):
    def test_partial_sweeps_say_so(self):
        result = ReconResult(ip="192.168.1.5", partial=True)
        self.assertIn("partial", format_recon(result))

    def test_summary_carries_kind_and_model(self):
        result = ReconResult(ip="192.168.1.5", device_kind="Printer",
                             upnp={"manufacturer": "Brother", "model_name": "L2350"})
        line = format_recon(result)
        self.assertIn("kind=Printer", line)
        self.assertIn("model=Brother L2350", line)


if __name__ == "__main__":
    unittest.main()
