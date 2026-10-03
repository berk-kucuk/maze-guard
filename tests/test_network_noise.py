"""
False alarms on ordinary network changes, and the detection that must survive
the fixes for them.

Every scenario here was a real report: the profile flipping between HOME and
PUBLIC on one WiFi network, "Gateway MAC changed — possible MITM" on walking
from home to the office, "Second DHCP server" on joining any network after the
first, a DANGEROUS "HTTPS downgrade" because a CDN refused a probe without SNI,
Pi-hole reported as DNS poisoning, and the TLS canary that stayed silent under
a real interceptor while alerting on certificate renewals.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import asyncio
import os
import ssl
import sys
import tempfile
import time
import types
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core.events import Event, EventBus, EventType, ThreatLevel  # noqa: E402
from maze.core.profile import Profile                                 # noqa: E402
from maze.detection import anomaly as anomaly_mod                     # noqa: E402
from maze.detection import arp_watch as arp_mod                       # noqa: E402
from maze.detection import rogue_ap as rogue_mod                      # noqa: E402
from maze.detection.anomaly import AnomalyDetector                    # noqa: E402
from maze.detection.arp_watch import ARPWatcher                       # noqa: E402
from maze.detection.dns_validator import DNSValidator, _classify      # noqa: E402
from maze.detection.rogue_ap import RogueAPDetector, _same_vendor     # noqa: E402
from maze.detection.ssl_strip import SSLStripDetector                 # noqa: E402
from maze.detection import tls_monitor as tls_mod                     # noqa: E402
from maze.network.auto_profile import AutoProfileWatcher              # noqa: E402
from maze.utils import network_info                                   # noqa: E402


def run(coro):
    return asyncio.run(coro)


class CollectingBus(EventBus):
    def __init__(self):
        super().__init__()
        self.events: list[Event] = []

    async def emit(self, event):
        self.events.append(event)

    def of(self, kind):
        return [e for e in self.events if e.type == kind]


# ── network identity ─────────────────────────────────────────────────────────

class TestNetworkIdentity(unittest.TestCase):

    def test_wifi_never_falls_back_to_the_gateway_mac(self):
        """One WiFi network used to have two ids; the profile flipped between them."""
        with unittest.mock.patch.object(network_info, "is_wireless", return_value=True), \
             unittest.mock.patch.object(network_info, "wifi_link", return_value=("", "")), \
             unittest.mock.patch.object(network_info, "_gateway_mac",
                                        return_value="aa:bb:cc:dd:ee:ff"):
            self.assertEqual(network_info.current_network_id("wlan0"), "")

    def test_wifi_is_identified_by_ssid(self):
        with unittest.mock.patch.object(network_info, "is_wireless", return_value=True), \
             unittest.mock.patch.object(network_info, "wifi_link",
                                        return_value=("Home", "aa:bb:cc:dd:ee:01")):
            self.assertEqual(network_info.current_network_id("wlan0"), "wifi:Home")

    def test_wired_is_identified_by_gateway_mac(self):
        with unittest.mock.patch.object(network_info, "is_wireless", return_value=False), \
             unittest.mock.patch.object(network_info, "_gateway_mac",
                                        return_value="aa:bb:cc:dd:ee:ff"):
            self.assertEqual(network_info.current_network_id("eth0"),
                             "gw:aa:bb:cc:dd:ee:ff")

    def test_wifi_link_falls_through_when_iw_is_missing(self):
        """iwgetid is not installed by default; iw or nmcli must answer."""
        def fake(cmd, **_kw):
            if cmd[0] == "iw":
                raise FileNotFoundError("iw")
            if cmd[0] == "nmcli":
                return "*:Home:AA\\:BB\\:CC\\:DD\\:EE\\:01\n :Other:11\\:22\\:33\\:44\\:55\\:66\n"
            raise AssertionError("iwgetid should not be needed")
        with unittest.mock.patch.object(network_info, "is_wireless", return_value=True), \
             unittest.mock.patch.object(network_info.subprocess, "check_output",
                                        side_effect=fake):
            self.assertEqual(network_info.wifi_link("wlan0"),
                             ("Home", "aa:bb:cc:dd:ee:01"))

    def test_aliases_include_the_legacy_gateway_id(self):
        with unittest.mock.patch.object(network_info, "current_network_id",
                                        return_value="wifi:Home"), \
             unittest.mock.patch.object(network_info, "_gateway_mac",
                                        return_value="aa:bb:cc:dd:ee:ff"):
            self.assertEqual(network_info.network_aliases("wlan0"),
                             {"wifi:Home", "gw:aa:bb:cc:dd:ee:ff"})

    def test_link_epoch_is_unknown_while_wifi_is_unreadable(self):
        with unittest.mock.patch.object(network_info, "is_wireless", return_value=True), \
             unittest.mock.patch.object(network_info, "wifi_link", return_value=("", "")):
            self.assertIsNone(network_info.link_epoch("wlan0"))


class _Identity:
    def __init__(self, net_id, aliases=None):
        self.interface = "wlan0"
        self.network_id = net_id
        self.aliases = aliases or {net_id}
        self._cb = None

    def on_change(self, cb):
        self._cb = cb

    def start(self):
        pass


class TestAutoProfile(unittest.TestCase):

    def test_a_network_trusted_under_its_old_gateway_id_is_still_home(self):
        ident = _Identity("wifi:Home", {"wifi:Home", "gw:aa:bb:cc:dd:ee:ff"})
        got = []
        watcher = AutoProfileWatcher(ident, ["gw:aa:bb:cc:dd:ee:ff"], got.append)
        watcher.start()
        self.assertEqual(got, [Profile.HOME])

    def test_the_same_verdict_is_not_applied_twice(self):
        """Re-applying overrode a manual choice and re-sent the notification."""
        ident = _Identity("wifi:Cafe")
        got = []
        watcher = AutoProfileWatcher(ident, [], got.append)
        watcher.start()
        watcher.set_trusted([])
        ident._cb("wifi:Cafe", "wifi:Cafe")
        self.assertEqual(got, [Profile.PUBLIC])

    def test_trusting_the_current_network_switches_to_home(self):
        ident = _Identity("wifi:Home")
        got = []
        watcher = AutoProfileWatcher(ident, [], got.append)
        watcher.start()
        watcher.set_trusted(["wifi:Home"])
        self.assertEqual(got, [Profile.PUBLIC, Profile.HOME])


# ── ARP watcher ──────────────────────────────────────────────────────────────

class TestGatewayBaseline(unittest.TestCase):

    def _watcher(self, gw=("192.168.1.1", "aa:aa:aa:aa:aa:01"), epoch=("3", "Home")):
        w = ARPWatcher("wlan0")
        w._bus = CollectingBus()
        w._gw_ip, w._gw_mac = gw
        w._epoch = epoch
        return w

    def _cycle(self, w, gw, epoch):
        with unittest.mock.patch.object(arp_mod, "_get_own_ips", return_value=set()), \
             unittest.mock.patch.object(arp_mod, "_get_gateway_info", return_value=gw), \
             unittest.mock.patch.object(arp_mod, "link_epoch", return_value=epoch):
            run(w._check_gateway())

    def test_moving_to_another_network_is_silent(self):
        w = self._watcher()
        w.devices["192.168.1.20"] = {"mac": "x"}
        new = ("192.168.1.1", "bb:bb:bb:bb:bb:02")
        for _ in range(3):
            self._cycle(w, new, ("4", "Office"))
        self.assertEqual(w._bus.events, [])
        self.assertEqual(w._gw_mac, "bb:bb:bb:bb:bb:02")
        self.assertEqual(w.devices, {})

    def test_a_gateway_mac_swap_on_a_steady_link_is_dangerous(self):
        w = self._watcher()
        new = ("192.168.1.1", "de:ad:be:ef:00:01")
        for _ in range(2):
            self._cycle(w, new, ("3", "Home"))
        spoof = w._bus.of(EventType.ARP_SPOOF)
        self.assertEqual(len(spoof), 1)
        self.assertEqual(spoof[0].level, ThreatLevel.DANGEROUS)

    def test_a_single_blip_is_not_reported(self):
        w = self._watcher()
        self._cycle(w, ("192.168.1.1", "de:ad:be:ef:00:01"), ("3", "Home"))
        self._cycle(w, ("192.168.1.1", "aa:aa:aa:aa:aa:01"), ("3", "Home"))
        self.assertEqual(w._bus.events, [])

    def test_a_gateway_address_change_is_only_suspicious(self):
        w = self._watcher()
        for _ in range(2):
            self._cycle(w, ("10.0.0.1", "aa:aa:aa:aa:aa:09"), ("3", "Home"))
        events = w._bus.of(EventType.ARP_SPOOF)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].level, ThreatLevel.SUSPICIOUS)

    def test_an_unreadable_epoch_does_not_reset(self):
        w = self._watcher()
        w.devices["192.168.1.20"] = {"mac": "x"}
        self._cycle(w, ("192.168.1.1", "aa:aa:aa:aa:aa:01"), None)
        self.assertIn("192.168.1.20", w.devices)

    def test_helper_packets_record_that_the_owner_is_alive(self):
        """Without this, every spoof seen via the helper was 'a reused lease'."""
        w = self._watcher()
        w._own_ips = set()
        with unittest.mock.patch.object(ARPWatcher, "_evaluate", return_value=None):
            run(w._on_helper_event({"event": "arp", "src": "192.168.1.30",
                                    "mac": "cc:cc:cc:cc:cc:03"}))
        self.assertIn("cc:cc:cc:cc:cc:03", w._mac_seen)


# ── anomaly detector ─────────────────────────────────────────────────────────

class TestAnomalyPerNetwork(unittest.TestCase):

    def _detector(self):
        det = AnomalyDetector("wlan0")
        det._bus = CollectingBus()
        det._epoch = ("3", "Home")
        det._epoch_started = time.monotonic() - 3600
        return det

    def _dhcp(self, det, server, epoch):
        with unittest.mock.patch.object(anomaly_mod, "link_epoch", return_value=epoch), \
             unittest.mock.patch.object(AnomalyDetector, "_refresh_gateway",
                                        new=unittest.mock.AsyncMock()):
            run(det._on_packet({"event": "dhcp", "src": server,
                                "server": server, "mtype": 5}))

    def test_the_next_networks_dhcp_server_is_not_a_second_one(self):
        det = self._detector()
        self._dhcp(det, "192.168.1.1", ("3", "Home"))
        self._dhcp(det, "10.0.0.1", ("4", "Office"))
        self.assertEqual(det._bus.of(EventType.ROGUE_DHCP), [])

    def test_a_second_server_on_the_same_link_is_still_reported(self):
        det = self._detector()
        self._dhcp(det, "192.168.1.1", ("3", "Home"))
        self._dhcp(det, "192.168.1.66", ("3", "Home"))
        self.assertEqual(len(det._bus.of(EventType.ROGUE_DHCP)), 1)

    def test_proxy_arp_by_the_gateway_is_exempt(self):
        """Guest WiFi answers for every client with the router's own MAC."""
        det = self._detector()
        det._gw_ip, det._gw_mac = "10.0.0.1", "aa:aa:aa:aa:aa:01"
        for i in range(10):
            run(det._on_packet({"event": "arp", "op": 2, "src": f"10.0.0.{20 + i}",
                                "mac": "AA:AA:AA:AA:AA:01", "dst": "10.0.0.5"}))
        self.assertEqual(det._bus.events, [])

    def test_mac_claims_age_out(self):
        det = self._detector()
        for i in range(4):
            run(det._on_packet({"event": "arp", "op": 2, "src": f"10.0.0.{20 + i}",
                                "mac": "cc:cc:cc:cc:cc:03", "dst": "10.0.0.5"}))
        det._mac_claims["cc:cc:cc:cc:cc:03"].started -= anomaly_mod._MAC_CLAIM_WINDOW + 1
        run(det._on_packet({"event": "arp", "op": 2, "src": "10.0.0.40",
                            "mac": "cc:cc:cc:cc:cc:03", "dst": "10.0.0.5"}))
        self.assertEqual(det._bus.events, [])

    def test_two_routers_answering_on_join_are_only_noted(self):
        det = self._detector()
        det._epoch_started = time.monotonic()
        with unittest.mock.patch.object(anomaly_mod, "link_epoch",
                                        return_value=("3", "Home")):
            for src in ("fe80::1", "fe80::2"):
                run(det._on_packet({"event": "ra", "src": src, "lifetime": 1800}))
        self.assertEqual(det._bus.of(EventType.ROGUE_RA), [])
        noted = det._bus.of(EventType.ANOMALY)
        self.assertEqual(len(noted), 1)
        self.assertEqual(noted[0].level, ThreatLevel.SUSPICIOUS)


# ── HTTPS downgrade probe ────────────────────────────────────────────────────

class TestTLSReachable(unittest.TestCase):

    def _probe(self, handshake_error=None, connect_error=None):
        sock = unittest.mock.MagicMock()
        wrapped = unittest.mock.MagicMock()
        wrapped.__enter__.return_value = wrapped
        with unittest.mock.patch("socket.create_connection",
                                 side_effect=connect_error, return_value=sock), \
             unittest.mock.patch.object(ssl.SSLContext, "wrap_socket",
                                        side_effect=handshake_error,
                                        return_value=wrapped):
            return SSLStripDetector._tls_reachable("203.0.113.9", "example.com")

    def test_a_tls_alert_means_the_port_is_alive(self):
        """CDNs answer a probe they dislike with an alert — that is TLS."""
        err = ssl.SSLError(1, "[SSL: TLSV1_ALERT_INTERNAL_ERROR] alert")
        self.assertTrue(self._probe(handshake_error=err))

    def test_a_cut_connection_is_dead(self):
        self.assertFalse(self._probe(handshake_error=ssl.SSLEOFError(8, "EOF")))

    def test_refused_is_dead(self):
        self.assertFalse(self._probe(connect_error=ConnectionRefusedError()))

    def test_a_completed_handshake_is_alive(self):
        self.assertTrue(self._probe())


# ── DNS validator ────────────────────────────────────────────────────────────

class TestDNSClassification(unittest.TestCase):

    def _validator(self, local, trusted={"1.1.1.1", "1.0.0.1"}):
        v = DNSValidator()
        v._bus = CollectingBus()

        async def doh(_url, _domain):
            return set(trusted)

        async def resolve(_domain):
            return set(local)
        v._doh_resolve = doh
        v._local_resolve = resolve
        return v

    def test_classify(self):
        self.assertEqual(_classify({"0.0.0.0"}), "sinkhole")
        self.assertEqual(_classify({"127.0.0.1"}), "sinkhole")
        self.assertEqual(_classify({"192.168.1.1"}), "private")
        self.assertEqual(_classify({"100.64.0.1"}), "private")
        self.assertEqual(_classify({"203.0.113.66"}), "public")
        self.assertEqual(_classify({"0.0.0.0", "203.0.113.66"}), "public")

    def test_a_pihole_block_is_not_poisoning(self):
        v = self._validator({"0.0.0.0"})
        self.assertTrue(run(v.validate("one.one.one.one")))
        self.assertEqual(v._bus.events, [])

    def test_a_captive_portal_answer_is_suspicious(self):
        v = self._validator({"10.1.1.1"})
        run(v.validate("one.one.one.one"))
        self.assertEqual([e.level for e in v._bus.events], [ThreatLevel.SUSPICIOUS])

    def test_a_foreign_public_answer_is_dangerous_once(self):
        v = self._validator({"203.0.113.66"})
        run(v.validate("one.one.one.one"))
        run(v.validate("one.one.one.one"))
        self.assertEqual([e.level for e in v._bus.events], [ThreatLevel.DANGEROUS])
        v.network_changed()
        run(v.validate("one.one.one.one"))
        self.assertEqual(len(v._bus.events), 2)

    def test_unreachable_doh_is_not_a_threat_event(self):
        v = self._validator({"1.1.1.1"}, trusted=set())
        run(v.validate("one.one.one.one"))
        self.assertEqual(v._bus.events, [])


# ── TLS canary ───────────────────────────────────────────────────────────────

class TestTLSCanary(unittest.TestCase):

    def _monitor(self, probe):
        m = tls_mod.TLSMonitor()
        m._bus = CollectingBus()
        m._spki_store["github.com"] = "old"
        m._probe = lambda _h, _p: probe
        return m

    def test_a_renewed_key_under_a_valid_chain_is_silent(self):
        m = self._monitor(tls_mod._Probe(True, "new", "CN=CA", ""))
        run(m.check("github.com"))
        self.assertEqual(m._bus.events, [])
        self.assertEqual(m._spki_store["github.com"], "new")

    def test_an_untrusted_certificate_is_reported_after_confirmation(self):
        """The case the old code was silent on: a real interceptor."""
        m = self._monitor(tls_mod._Probe(False, "evil", "CN=mitmproxy",
                                         "self-signed certificate"))
        run(m.check("github.com"))
        self.assertEqual(m._bus.events, [])
        run(m.check("github.com"))
        events = m._bus.of(EventType.TLS_CHANGE)
        self.assertEqual(len(events), 1)
        self.assertIn("mitmproxy", events[0].message)

    def test_an_expired_certificate_is_not_excused_on_a_sane_clock(self):
        probe = tls_mod._Probe(False, "evil", "CN=x", "certificate has expired")
        self.assertFalse(probe.clock_problem)
        with unittest.mock.patch.object(tls_mod.time, "time", return_value=0):
            self.assertTrue(probe.clock_problem)


# ── evil twin ────────────────────────────────────────────────────────────────

class TestEvilTwinNoise(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = unittest.mock.patch.object(
            rogue_mod, "_KNOWN_FILE", Path(self._tmp.name) / "known-aps.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _detector(self):
        det = RogueAPDetector("wlan0")
        det._bus = CollectingBus()
        det._adopt("Home", "a4:2b:b0:11:22:30")
        return det

    def _confirm(self, det, bssid):
        for _ in range(rogue_mod._BSSID_CONFIRM_COUNT):
            run(det._check_bssid("Home", bssid))

    def test_same_vendor(self):
        self.assertTrue(_same_vendor("a4:2b:b0:11:22:30", "a4:2b:b0:11:22:31"))
        self.assertTrue(_same_vendor("a4:2b:b0:11:22:30", "a6:2b:b0:11:22:30"))
        self.assertFalse(_same_vendor("a4:2b:b0:11:22:30", "00:c0:ca:99:88:77"))

    def test_the_other_band_of_the_same_router_is_silent(self):
        det = self._detector()
        self._confirm(det, "a4:2b:b0:11:22:31")
        self.assertEqual(det._bus.events, [])

    def test_a_different_vendor_is_reported(self):
        det = self._detector()
        self._confirm(det, "00:c0:ca:99:88:77")
        self.assertEqual(len(det._bus.of(EventType.ROGUE_AP)), 1)

    def test_known_access_points_survive_a_restart(self):
        det = self._detector()
        self._confirm(det, "00:c0:ca:99:88:77")
        again = RogueAPDetector("wlan0")
        again._bus = CollectingBus()
        again._adopt("Home", "a4:2b:b0:11:22:30")
        self._confirm(again, "00:c0:ca:99:88:77")
        self.assertEqual(again._bus.events, [])

    def test_default_alone_does_not_expose_the_interface(self):
        values = {"all": "0", "default": "1", "wlan0": "0"}

        def fake_open(path, *_a, **_k):
            scope = path.split("/")[-2]
            name = path.split("/")[-1]
            val = "0" if name == "forwarding" else values[scope]
            return unittest.mock.mock_open(read_data=val)()
        det = RogueAPDetector("wlan0")
        with unittest.mock.patch("builtins.open", side_effect=fake_open):
            self.assertEqual(det._enabled_scopes("ipv4", "accept_redirects"), [])
            values["all"] = "1"
            self.assertEqual(det._enabled_scopes("ipv4", "accept_redirects"),
                             ["net.ipv4.conf.all.accept_redirects"])
            self.assertEqual(det._enabled_scopes("ipv6", "accept_redirects"), [])


# ── popup damping ────────────────────────────────────────────────────────────

class TestPopupDamping(unittest.TestCase):

    def setUp(self):
        try:
            from maze.gui.dashboard import Dashboard
        except Exception as exc:          # no Qt in this environment
            self.skipTest(f"dashboard not importable: {exc}")
        self.fn = Dashboard._popup_allowed
        self.host = types.SimpleNamespace(
            _popup_last={}, _popup_times={},
            _POPUP_REPEAT=Dashboard._POPUP_REPEAT,
            _POPUP_WINDOW=Dashboard._POPUP_WINDOW,
            _POPUP_BURST=Dashboard._POPUP_BURST)

    def _event(self, src):
        return Event(type=EventType.ARP_SPOOF, level=ThreatLevel.DANGEROUS,
                     message="x", data={"ip": src})

    def test_the_same_finding_pops_once(self):
        self.assertTrue(self.fn(self.host, self._event("10.0.0.9")))
        self.assertFalse(self.fn(self.host, self._event("10.0.0.9")))

    def test_a_burst_is_capped(self):
        allowed = [self.fn(self.host, self._event(f"10.0.0.{i}")) for i in range(6)]
        self.assertEqual(allowed.count(True), 3)


if __name__ == "__main__":
    unittest.main()
