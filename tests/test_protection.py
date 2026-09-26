"""
Unit tests for the protection and stealth modules.

Every one of these covers a case where the module used to report itself Active
while doing nothing — the failure mode that matters most in a security tool,
because it is indistinguishable from working right up until it matters.

No root, no network, no real firewall: a stub helper stands in for the daemon.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import asyncio
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core.events import Event, EventBus, EventType, ThreatLevel  # noqa: E402
from maze.core.verify import (FAIL, INFO, NA, PASS, WARN, Verdict,  # noqa: E402
                              capture_feed, merge)
from maze.detection.anomaly import AnomalyDetector                   # noqa: E402
from maze.protection.port_scanner import PortScanDetector            # noqa: E402
from maze.detection.rogue_ap import RogueAPDetector                   # noqa: E402
from maze.detection.ssl_strip import SSLStripDetector                 # noqa: E402
from maze.protection.dns_leak import DNSLeakPreventer                 # noqa: E402
from maze.stealth.fingerprint import FingerprintProtector             # noqa: E402
from maze.stealth.hostname_hide import HostnameHider, _SOCKET, _UNIT  # noqa: E402
from maze.stealth.service_blocker import ServiceBlocker, _BLOCKED     # noqa: E402


def run(coro):
    return asyncio.run(coro)


class RecordingBus(EventBus):
    """Event bus that keeps what was emitted so a test can inspect it."""

    def __init__(self):
        super().__init__()
        self.events: list[Event] = []
        self.subscribe_all(self._record)

    async def _record(self, event: Event) -> None:
        self.events.append(event)

    def types(self):
        return [e.type for e in self.events]


class StubHelper:
    """Minimal stand-in for the privileged daemon."""

    def __init__(self, connected=True, running=True, zone="public"):
        self._connected = connected
        self.state = {"installed": True, "running": running, "enabled": True,
                      "zone": zone, "target": "default", "panic": False}
        self.fw_calls: list[list[str]] = []
        self.sysctl: dict[str, str] = {
            "net.ipv4.ip_default_ttl": "64",
            "net.ipv6.conf.all.hop_limit": "64",
            "net.ipv4.tcp_timestamps": "1",
        }
        self.accept = True

    def is_connected(self):
        return self._connected

    async def fw_state(self):
        return dict(self.state)

    async def fw_list_all(self):
        return f"{self.state['zone']} (default, active)\n"

    async def fw_cmd(self, args):
        self.fw_calls.append(args)
        return self.accept

    async def fw_list(self):
        # Deliberately empty unless a test says otherwise: "we sent the rules"
        # and "the firewall is holding them" are different claims, and the
        # verifier exists to tell them apart.
        return {"ips": [], "ports_tcp": [], "ports_udp": []}

    async def sysctl_get(self, key):
        return self.sysctl.get(key)

    async def sysctl_set(self, key, value):
        if key not in self.sysctl:
            return False
        self.sysctl[key] = value
        return True

    def on_event(self, cb):
        pass

    def off_event(self, cb):
        pass

    # ── what a test wants to know ────────────────────────────────────────

    def rules(self, action="--add-rich-rule"):
        return [args[args.index(action) + 1] for args in self.fw_calls
                if action in args]


# ── Service blocker ──────────────────────────────────────────────────────────

class TestServiceBlocker(unittest.TestCase):

    def test_refuses_to_start_without_the_helper(self):
        # It used to set itself active regardless, so the interface showed a
        # green "Active" for rules that were never installed.
        blocker = ServiceBlocker()
        with self.assertRaises(PermissionError):
            run(blocker.start(None, helper=None))

    def test_refuses_to_start_when_the_firewall_is_stopped(self):
        helper = StubHelper(running=False)
        blocker = ServiceBlocker()
        with self.assertRaises(RuntimeError):
            run(blocker.start(None, helper=helper))

    def test_every_port_is_blocked_in_both_families(self):
        helper = StubHelper()
        blocker = ServiceBlocker()
        run(blocker.start(None, helper=helper))
        added = helper.rules()
        self.assertEqual(len(added), len(_BLOCKED) * 2)
        for proto, port, _why in _BLOCKED:
            for family in ("ipv4", "ipv6"):
                self.assertIn(
                    f"rule family={family} port port={port} "
                    f"protocol={proto} drop", added)

    def test_rules_name_the_zone_the_firewall_reported(self):
        # Without --zone the rules land in whatever firewalld calls default at
        # that moment, which is not necessarily the zone the rest of the
        # application is operating on.
        helper = StubHelper(zone="home")
        blocker = ServiceBlocker()
        run(blocker.start(None, helper=helper))
        for args in helper.fw_calls:
            if "--add-rich-rule" in args:
                self.assertEqual(args[args.index("--zone") + 1], "home")

    def test_a_firewall_that_accepts_nothing_is_reported(self):
        helper = StubHelper()
        helper.accept = False
        blocker = ServiceBlocker()
        with self.assertRaises(RuntimeError):
            run(blocker.start(None, helper=helper))

    def test_stop_removes_exactly_what_was_added(self):
        helper = StubHelper()
        blocker = ServiceBlocker()
        run(blocker.start(None, helper=helper))
        added = set(helper.rules())
        run(blocker.stop())
        self.assertEqual(set(helper.rules("--remove-rich-rule")), added)

    def test_status_says_which_ports_are_dropped(self):
        helper = StubHelper()
        blocker = ServiceBlocker()
        run(blocker.start(None, helper=helper))
        detail = blocker.status_detail()
        self.assertIn("udp/5353", detail)
        self.assertIn("tcp/445", detail)


# ── HTTPS downgrade ──────────────────────────────────────────────────────────

class TestSSLStripDetector(unittest.TestCase):

    def setUp(self):
        self.bus = RecordingBus()
        self.det = SSLStripDetector()
        run(self.det.start(self.bus))

    def _probe(self, reachable: bool):
        return unittest.mock.patch.object(
            SSLStripDetector, "_tls_reachable", staticmethod(lambda ip, *_a: reachable))

    def test_an_unknown_address_is_never_reported(self):
        # Plaintext HTTP to a host we have never seen serve TLS is just HTTP.
        with self._probe(False):
            run(self.det.check_downgrade("203.0.113.9"))
        self.assertEqual(self.bus.events, [])

    def test_a_reachable_tls_port_is_not_a_downgrade(self):
        self.det.note_tls_endpoint("203.0.113.9")
        with self._probe(True):
            run(self.det.check_downgrade("203.0.113.9"))
        self.assertEqual(self.bus.events, [])

    def test_one_failure_is_not_enough(self):
        self.det.note_tls_endpoint("203.0.113.9")
        with self._probe(False):
            run(self.det.check_downgrade("203.0.113.9"))
        self.assertEqual(self.bus.events, [])

    def test_a_confirmed_dead_tls_port_is_reported(self):
        self.det.note_tls_endpoint("203.0.113.9")
        with self._probe(False):
            run(self.det.check_downgrade("203.0.113.9"))
            self.det._probed.clear()      # stand in for the retry delay
            run(self.det.check_downgrade("203.0.113.9"))
        self.assertEqual(self.bus.types(), [EventType.SSL_STRIP])
        event = self.bus.events[0]
        self.assertEqual(event.level, ThreatLevel.DANGEROUS)
        self.assertEqual(event.data["ip"], "203.0.113.9")

    def test_the_same_address_is_not_re_probed_immediately(self):
        # The engine offers every plaintext connection on every pass; probing
        # 443 each time would turn a busy browsing session into a connection
        # storm of our own making.
        self.det.note_tls_endpoint("203.0.113.9")
        with self._probe(False):
            run(self.det.check_downgrade("203.0.113.9"))
            run(self.det.check_downgrade("203.0.113.9"))
            run(self.det.check_downgrade("203.0.113.9"))
        self.assertEqual(self.det._failures["203.0.113.9"], 1)

    def test_recovery_clears_the_failure_count(self):
        self.det.note_tls_endpoint("203.0.113.9")
        with self._probe(False):
            run(self.det.check_downgrade("203.0.113.9"))
        self.det._probed.clear()
        with self._probe(True):
            run(self.det.check_downgrade("203.0.113.9"))
        self.det._probed.clear()
        with self._probe(False):
            run(self.det.check_downgrade("203.0.113.9"))
        self.assertEqual(self.bus.events, [])

    def test_an_endpoint_is_forgotten_once_it_ages_out(self):
        self.det.note_tls_endpoint("203.0.113.9")
        self.det._tls_hosts["203.0.113.9"] -= 7 * 3600
        self.assertFalse(self.det.knows_tls("203.0.113.9"))


# ── Rogue AP / route hijack ──────────────────────────────────────────────────

class TestRogueAPDetector(unittest.TestCase):

    def test_nmcli_output_is_parsed_despite_escaped_colons(self):
        det = RogueAPDetector("wlan0")
        line = "*:CoffeeShop:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n"
        with unittest.mock.patch("subprocess.check_output", return_value=line):
            ssid, bssid = det._ap_via_nmcli()
        self.assertEqual(ssid, "CoffeeShop")
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:FF")

    def test_iw_output_is_parsed(self):
        det = RogueAPDetector("wlan0")
        out = ("Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n"
               "\tSSID: Airport Free WiFi\n\tfreq: 2437\n")
        with unittest.mock.patch("subprocess.check_output", return_value=out):
            ssid, bssid = det._ap_via_iw()
        self.assertEqual(ssid, "Airport Free WiFi")
        self.assertEqual(bssid, "aa:bb:cc:dd:ee:ff")

    def test_a_disconnected_interface_yields_nothing(self):
        det = RogueAPDetector("wlan0")
        with unittest.mock.patch("subprocess.check_output",
                                 return_value="Not connected.\n"):
            self.assertEqual(det._ap_via_iw(), (None, None))

    def test_iwgetid_failure_falls_through_to_the_next_tool(self):
        det = RogueAPDetector("wlan0")
        with unittest.mock.patch.object(
                RogueAPDetector, "_ap_via_iw",
                side_effect=FileNotFoundError("no iw")), \
             unittest.mock.patch.object(
                RogueAPDetector, "_ap_via_iwgetid",
                side_effect=FileNotFoundError("no iwgetid")), \
             unittest.mock.patch.object(
                RogueAPDetector, "_ap_via_nmcli",
                return_value=("Mesh", "11:22:33:44:55:66")):
            self.assertEqual(det._current_ap(), ("Mesh", "11:22:33:44:55:66"))

    def test_redirect_exposure_is_reported_on_a_wired_link(self):
        # The whole module used to be gated on the interface being wireless, so
        # on an Ethernet machine it ran and reported nothing, ever.
        bus = RecordingBus()
        det = RogueAPDetector("enp0s1")
        det._bus = bus
        with unittest.mock.patch.object(
                RogueAPDetector, "_enabled_scopes",
                return_value=["net.ipv4.conf.all.accept_redirects"]):
            run(det._check_redirects())
        self.assertIn(EventType.ROGUE_AP, bus.types())

    def test_redirect_exposure_is_reported_once(self):
        bus = RecordingBus()
        det = RogueAPDetector("enp0s1")
        det._bus = bus
        with unittest.mock.patch.object(
                RogueAPDetector, "_enabled_scopes",
                return_value=["net.ipv4.conf.all.accept_redirects"]):
            run(det._check_redirects())
            run(det._check_redirects())
        self.assertEqual(len(bus.events), 2)   # one per family, not per pass

    def test_turning_the_setting_off_rearms_the_warning(self):
        bus = RecordingBus()
        det = RogueAPDetector("enp0s1")
        det._bus = bus
        on = ["net.ipv4.conf.all.accept_redirects"]
        with unittest.mock.patch.object(RogueAPDetector, "_enabled_scopes",
                                        return_value=on):
            run(det._check_redirects())
        with unittest.mock.patch.object(RogueAPDetector, "_enabled_scopes",
                                        return_value=[]):
            run(det._check_redirects())
        with unittest.mock.patch.object(RogueAPDetector, "_enabled_scopes",
                                        return_value=on):
            run(det._check_redirects())
        self.assertEqual(len(bus.events), 4)

    def test_a_wired_link_says_so_rather_than_claiming_to_watch_an_ap(self):
        det = RogueAPDetector("enp0s1")
        det._is_wifi = False
        self.assertIn("not wireless", det.status_detail())


# ── Fingerprint protection ───────────────────────────────────────────────────

class TestFingerprintProtector(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "fingerprint-state"
        self.patch = unittest.mock.patch(
            "maze.stealth.fingerprint._STATE_FILE", self.state)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_refuses_to_start_without_the_helper(self):
        with self.assertRaises(PermissionError):
            run(FingerprintProtector().start(None, helper=None))

    def test_window_scaling_is_left_alone(self):
        # Disabling it costs real throughput on any fast link, for a
        # fingerprinting bit barely worth the trade.
        helper = StubHelper()
        run(FingerprintProtector().start(None, helper=helper))
        self.assertNotIn("net.ipv4.tcp_window_scaling", helper.sysctl)

    def test_the_values_are_applied_and_restored(self):
        helper = StubHelper()
        prot = FingerprintProtector()
        run(prot.start(None, helper=helper))
        self.assertEqual(helper.sysctl["net.ipv4.ip_default_ttl"], "128")
        self.assertEqual(helper.sysctl["net.ipv4.tcp_timestamps"], "0")
        run(prot.stop())
        self.assertEqual(helper.sysctl["net.ipv4.ip_default_ttl"], "64")
        self.assertEqual(helper.sysctl["net.ipv4.tcp_timestamps"], "1")

    def test_the_originals_are_written_down(self):
        helper = StubHelper()
        run(FingerprintProtector().start(None, helper=helper))
        saved = json.loads(self.state.read_text())
        self.assertEqual(saved["net.ipv4.ip_default_ttl"], "64")

    def test_a_crash_does_not_lose_the_original_values(self):
        # First run applies the settings and then dies without stopping: the
        # state file is all that remembers what the machine looked like.
        helper = StubHelper()
        run(FingerprintProtector().start(None, helper=helper))
        self.assertEqual(helper.sysctl["net.ipv4.ip_default_ttl"], "128")

        second = FingerprintProtector()
        run(second.start(None, helper=helper))
        run(second.stop())
        self.assertEqual(helper.sysctl["net.ipv4.ip_default_ttl"], "64")
        self.assertEqual(helper.sysctl["net.ipv4.tcp_timestamps"], "1")
        self.assertFalse(self.state.exists())

    def test_a_helper_that_knows_none_of_the_keys_is_reported(self):
        helper = StubHelper()
        helper.sysctl = {}
        with self.assertRaises(RuntimeError):
            run(FingerprintProtector().start(None, helper=helper))

    def test_a_kernel_already_at_the_target_is_not_a_failure(self):
        # The one machine reported as broken was the one already protected:
        # nothing needed changing, and that was mistaken for nothing working.
        helper = StubHelper()
        helper.sysctl = {"net.ipv4.ip_default_ttl": "128",
                         "net.ipv6.conf.all.hop_limit": "128",
                         "net.ipv4.tcp_timestamps": "0"}
        prot = FingerprintProtector()
        run(prot.start(None, helper=helper))          # must not raise
        self.assertEqual(run(prot.verify()).status, PASS)
        self.assertIn("already held", prot.status_detail())

    def test_values_already_at_the_target_are_left_alone_on_stop(self):
        helper = StubHelper()
        helper.sysctl = {"net.ipv4.ip_default_ttl": "128",
                         "net.ipv6.conf.all.hop_limit": "128",
                         "net.ipv4.tcp_timestamps": "0"}
        prot = FingerprintProtector()
        run(prot.start(None, helper=helper))
        run(prot.stop())
        self.assertEqual(helper.sysctl["net.ipv4.ip_default_ttl"], "128")

    def test_a_kernel_that_refuses_every_change_is_a_failure(self):
        helper = StubHelper()
        helper.sysctl_set = lambda key, value: _answer(False)
        with self.assertRaises(RuntimeError):
            run(FingerprintProtector().start(None, helper=helper))

    def test_the_originals_are_recorded_before_anything_is_written(self):
        # A crash between the write and the record loses what the machine
        # looked like, and no later run can recover it.
        helper = StubHelper()
        state = self.state
        written: list[bool] = []

        original_set = helper.sysctl_set

        async def _watched(key, value):
            written.append(state.exists())
            return await original_set(key, value)

        helper.sysctl_set = _watched
        run(FingerprintProtector().start(None, helper=helper))
        self.assertTrue(written and all(written))


# ── Hostname hiding ──────────────────────────────────────────────────────────

class ServiceHelper(StubHelper):
    """Stub whose systemd units can be started and stopped."""

    def __init__(self, active=(_UNIT, _SOCKET)):
        super().__init__()
        self.units = {u: (u in active) for u in (_UNIT, _SOCKET)}
        self.actions: list[tuple[str, str]] = []

    async def svc(self, action, unit):
        if action == "is-active":
            return True, "active" if self.units.get(unit) else "inactive"
        self.actions.append((action, unit))
        self.units[unit] = (action == "start")
        return True, ""


class TestHostnameHider(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "hostname-state"
        self.patch = unittest.mock.patch(
            "maze.stealth.hostname_hide._STATE_FILE", self.state)
        self.patch.start()
        self.exists = unittest.mock.patch.object(
            HostnameHider, "_unit_exists", staticmethod(lambda: True))
        self.exists.start()

    def tearDown(self):
        self.exists.stop()
        self.patch.stop()
        self.tmp.cleanup()

    def test_refuses_to_start_without_the_helper(self):
        with unittest.mock.patch("os.getuid", return_value=1000):
            with self.assertRaises(PermissionError):
                run(HostnameHider().start(None, helper=None))

    def test_the_activation_socket_is_stopped_before_the_service(self):
        # Stopping the service first lets nss-mdns re-trigger it through the
        # socket before the socket itself is disarmed.
        helper = ServiceHelper()
        run(HostnameHider().start(None, helper=helper))
        self.assertEqual(helper.actions,
                         [("stop", _SOCKET), ("stop", _UNIT)])
        self.assertFalse(helper.units[_UNIT])
        self.assertFalse(helper.units[_SOCKET])

    def test_a_stopped_service_still_leaves_the_socket_to_disarm(self):
        # The state this machine is actually in: the responder is not running,
        # but systemd is listening on its behalf and will start it on demand.
        helper = ServiceHelper(active=(_SOCKET,))
        hider = HostnameHider()
        run(hider.start(None, helper=helper))
        self.assertEqual(helper.actions, [("stop", _SOCKET)])
        self.assertIn("activation socket", hider.status_detail())

    def test_both_units_are_restored_in_reverse(self):
        helper = ServiceHelper()
        hider = HostnameHider()
        run(hider.start(None, helper=helper))
        helper.actions.clear()
        run(hider.stop())
        self.assertEqual(helper.actions,
                         [("start", _UNIT), ("start", _SOCKET)])

    def test_only_what_was_running_comes_back(self):
        helper = ServiceHelper(active=(_SOCKET,))
        hider = HostnameHider()
        run(hider.start(None, helper=helper))
        helper.actions.clear()
        run(hider.stop())
        self.assertEqual(helper.actions, [("start", _SOCKET)])

    def test_a_crash_does_not_strand_avahi(self):
        helper = ServiceHelper()
        run(HostnameHider().start(None, helper=helper))   # dies without stop()
        self.assertTrue(self.state.exists())

        second = HostnameHider()
        second._helper = helper
        run(second.stop())
        self.assertTrue(helper.units[_UNIT])
        self.assertTrue(helper.units[_SOCKET])
        self.assertFalse(self.state.exists())

    def test_a_state_file_from_the_previous_version_is_understood(self):
        # It held a bare "1" meaning "the service was running".
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("1")
        helper = ServiceHelper(active=())
        hider = HostnameHider()
        hider._helper = helper
        run(hider.stop())
        self.assertEqual(helper.actions, [("start", _UNIT)])


# ── DNS leak / hijack ────────────────────────────────────────────────────────

class TestDNSLeakPreventer(unittest.TestCase):

    def _preventer(self, configured, upstreams, vpn):
        prev = DNSLeakPreventer()
        prev._config = (set(configured), set(upstreams), list(vpn))
        prev._config_at = float("inf")     # never expire during the test
        return prev

    def test_the_configured_resolver_is_not_a_leak(self):
        prev = self._preventer({"127.0.0.53"}, set(), [])
        self.assertIsNone(prev._judge("127.0.0.53"))

    def test_the_resolver_daemons_own_upstream_is_not_a_leak(self):
        prev = self._preventer({"127.0.0.53"}, {"1.1.1.1"}, [])
        self.assertIsNone(prev._judge("1.1.1.1"))

    def test_a_stranger_resolver_without_vpn_is_a_hijack(self):
        prev = self._preventer({"127.0.0.53"}, {"1.1.1.1"}, [])
        self.assertIn("hijack", prev._judge("45.33.12.9"))

    def test_the_lan_router_without_vpn_is_normal(self):
        prev = self._preventer({"127.0.0.53"}, set(), [])
        self.assertIsNone(prev._judge("192.168.1.1"))

    def test_under_a_vpn_a_query_through_the_tunnel_is_fine(self):
        prev = self._preventer({"127.0.0.53"}, set(), ["tun0"])
        with unittest.mock.patch("maze.protection.dns_leak._dns_egress_iface",
                                 return_value="tun0"):
            self.assertIsNone(prev._judge("9.9.9.9"))

    def test_under_a_vpn_a_query_around_the_tunnel_is_a_leak(self):
        prev = self._preventer({"127.0.0.53"}, set(), ["tun0"])
        with unittest.mock.patch("maze.protection.dns_leak._dns_egress_iface",
                                 return_value="enp0s1"):
            verdict = prev._judge("9.9.9.9")
        self.assertIn("egresses via 'enp0s1'", verdict)

    def test_a_live_query_raises_the_event(self):
        # The poll could only ever catch a socket still open 60 seconds later;
        # an application's own DNS query is finished in milliseconds.
        bus = RecordingBus()
        prev = self._preventer({"127.0.0.53"}, set(), [])
        prev._bus = bus
        run(prev._on_helper_event({"event": "dns", "outbound": True,
                                   "dport": 53, "dst": "45.33.12.9"}))
        self.assertEqual(bus.types(), [EventType.DNS_LEAK])

    def test_an_incoming_answer_is_not_examined(self):
        bus = RecordingBus()
        prev = self._preventer({"127.0.0.53"}, set(), [])
        prev._bus = bus
        run(prev._on_helper_event({"event": "dns", "outbound": False,
                                   "sport": 53, "dport": 41234,
                                   "dst": "192.168.1.10"}))
        self.assertEqual(bus.events, [])

    def test_one_address_is_not_reported_twice_in_a_row(self):
        bus = RecordingBus()
        prev = self._preventer({"127.0.0.53"}, set(), [])
        prev._bus = bus
        msg = {"event": "dns", "outbound": True, "dport": 53,
               "dst": "45.33.12.9"}
        run(prev._on_helper_event(dict(msg)))
        prev._judged.clear()               # allow a re-judge, as time would
        run(prev._on_helper_event(dict(msg)))
        self.assertEqual(len(bus.events), 1)




# ── Self-tests ───────────────────────────────────────────────────────────────

class TestVerdictMerge(unittest.TestCase):

    def test_the_worst_status_decides(self):
        v = merge(Verdict(PASS, "capture is live"),
                  Verdict(FAIL, "the alarm never fired"))
        self.assertEqual(v.status, FAIL)
        self.assertEqual(v.summary, "the alarm never fired")

    def test_the_other_summaries_survive_as_evidence(self):
        v = merge(Verdict(PASS, "capture is live"), Verdict(FAIL, "broken"))
        self.assertIn("capture is live", v.evidence)

    def test_a_clean_run_stays_clean(self):
        self.assertTrue(merge(Verdict(PASS, "a"), Verdict(INFO, "b")).ok)


class TestModuleSelfTests(unittest.TestCase):
    """Every verifier must answer from the system, in both toggle states."""

    def test_the_port_scanner_proves_its_own_alarm(self):
        det = PortScanDetector("lo", threshold=10)
        det._capture = "helper"
        det._seen = 5
        det._own_ips = {"10.0.0.1"}
        verdict = run(det.verify())
        self.assertEqual(verdict.status, PASS)
        self.assertIn("sweep", verdict.summary + " ".join(verdict.evidence))

    def test_the_port_scanner_reports_a_dead_capture(self):
        det = PortScanDetector("lo", threshold=10)   # never started
        verdict = run(det.verify())
        self.assertEqual(verdict.status, FAIL)
        self.assertIn("no capture", verdict.summary)

    def test_the_self_test_leaves_the_live_detector_alone(self):
        # The synthetic sweep must not appear in the real detector's evidence,
        # or a test would invent an attacker in the Threats tab.
        det = PortScanDetector("lo", threshold=10)
        det._capture = "helper"
        det._own_ips = {"10.0.0.1"}
        run(det.verify())
        self.assertEqual(det._records, {})

    def test_the_anomaly_detector_proves_its_own_alarm(self):
        det = AnomalyDetector("lo")
        det._live = True
        det._seen = 3
        verdict = run(det.verify())
        self.assertEqual(verdict.status, PASS)

    def test_the_anomaly_detector_reports_a_missing_feed(self):
        det = AnomalyDetector("lo")
        verdict = run(det.verify())
        self.assertEqual(verdict.status, FAIL)
        self.assertIn("no packet feed", verdict.summary)

    def test_the_service_blocker_asks_the_firewall_not_itself(self):
        helper = StubHelper()
        blocker = ServiceBlocker()
        run(blocker.start(None, helper=helper))
        # The stub records rules but reports an empty live list — exactly the
        # case that used to pass silently.
        verdict = run(blocker.verify())
        self.assertEqual(verdict.status, FAIL)
        self.assertIn("none of the discovery-port block rules", verdict.summary)

    def test_the_service_blocker_confirms_rules_the_firewall_holds(self):
        helper = StubHelper()
        blocker = ServiceBlocker()
        blocker._helper = helper
        helper.fw_list = lambda: _answer({
            "ips": [],
            "ports_tcp": [139, 445],
            "ports_udp": [5353, 5355, 137, 138, 1900, 3702],
        })
        verdict = run(blocker.verify())
        self.assertEqual(verdict.status, PASS)

    def test_a_half_applied_service_block_is_not_called_success(self):
        helper = StubHelper()
        blocker = ServiceBlocker()
        blocker._helper = helper
        helper.fw_list = lambda: _answer(
            {"ips": [], "ports_tcp": [], "ports_udp": [5353]})
        verdict = run(blocker.verify())
        self.assertEqual(verdict.status, WARN)
        self.assertTrue(any("445" in e for e in verdict.evidence))

    def test_the_fingerprint_test_reads_the_kernel_back(self):
        helper = StubHelper()
        prot = FingerprintProtector()
        self.assertEqual(run(prot_verify(prot, helper)).status, FAIL)  # untouched
        run(prot.start(None, helper=helper))
        self.assertEqual(run(prot.verify()).status, PASS)
        run(prot.stop())
        self.assertEqual(run(prot.verify()).status, FAIL)

    def test_the_hostname_test_reads_systemd_back(self):
        hider = HostnameHider()
        with unittest.mock.patch.object(HostnameHider, "_unit_exists",
                                        staticmethod(lambda: True)), \
             unittest.mock.patch.object(HostnameHider, "_is_active_direct",
                                        staticmethod(lambda unit: False)):
            self.assertEqual(run(hider.verify()).status, PASS)

    def test_an_armed_activation_socket_is_not_called_success(self):
        hider = HostnameHider()
        with unittest.mock.patch.object(HostnameHider, "_unit_exists",
                                        staticmethod(lambda: True)), \
             unittest.mock.patch.object(
                 HostnameHider, "_is_active_direct",
                 staticmethod(lambda unit: unit.endswith(".socket"))):
            verdict = run(hider.verify())
        self.assertEqual(verdict.status, FAIL)
        self.assertIn("still armed", verdict.summary)

    def test_the_dns_leak_rule_is_exercised_with_a_reserved_address(self):
        prev = DNSLeakPreventer()
        prev._config = ({"127.0.0.53"}, {"1.1.1.1"}, [])
        prev._config_at = float("inf")
        verdict = prev._verify_rule()
        self.assertEqual(verdict.status, PASS)
        self.assertIn("198.51.100.53", verdict.summary)

    def test_a_dns_leak_rule_that_stopped_firing_is_caught(self):
        prev = DNSLeakPreventer()
        # Pretend the reserved probe address is a legitimate upstream: the rule
        # then has nothing to flag, which is what a broken rule looks like.
        prev._config = ({"127.0.0.53"}, {"198.51.100.53"}, [])
        prev._config_at = float("inf")
        self.assertEqual(prev._verify_rule().status, FAIL)

    def test_the_downgrade_probe_is_exercised(self):
        det = SSLStripDetector()
        det.note_tls_endpoint("203.0.113.9")
        with unittest.mock.patch.object(
                SSLStripDetector, "_tls_reachable", staticmethod(lambda ip, *_a: True)):
            self.assertEqual(run(det.verify()).status, PASS)

    def test_a_probe_that_cannot_reach_the_network_is_a_failure(self):
        det = SSLStripDetector()
        det.note_tls_endpoint("203.0.113.9")
        with unittest.mock.patch.object(
                SSLStripDetector, "_tls_reachable", staticmethod(lambda ip, *_a: False)):
            self.assertEqual(run(det.verify()).status, FAIL)


class TestCaptureFeedVerdict(unittest.TestCase):
    """Quiet and dead look identical from the client; the daemon knows which."""

    class _Counting:
        def __init__(self, packets):
            self._packets = packets

        def is_connected(self):
            return True

        async def capture_stats(self):
            return {"packets": self._packets, "pushed": 0,
                    "iface": "enp0s1", "uptime_s": 120.0}

    def test_no_capture_at_all_is_a_failure(self):
        v = run(capture_feed(None, "", 0, "ARP packets"))
        self.assertEqual(v.status, FAIL)

    def test_packets_seen_by_the_detector_pass(self):
        v = run(capture_feed(None, "helper", 12, "ARP packets"))
        self.assertEqual(v.status, PASS)

    def test_a_quiet_network_is_not_reported_as_degraded(self):
        # A healthy machine nobody is attacking must not sit at amber; that is
        # how a warning stops meaning anything.
        v = run(capture_feed(self._Counting(5000), "helper", 0, "ARP packets"))
        self.assertEqual(v.status, PASS)
        self.assertIn("nothing has been aimed at this machine", v.summary)

    def test_a_dead_feed_is_reported_as_dead(self):
        v = run(capture_feed(self._Counting(0), "helper", 0, "ARP packets"))
        self.assertEqual(v.status, FAIL)
        self.assertIn("dead", v.summary)

    def test_an_old_daemon_cannot_tell_and_says_so(self):
        class _Old:
            def is_connected(self):
                return True

            async def capture_stats(self):
                return {}

        v = run(capture_feed(_Old(), "helper", 0, "ARP packets"))
        self.assertEqual(v.status, WARN)
        self.assertIn("too old", v.summary)

    def test_capturing_without_the_helper_is_flagged(self):
        v = run(capture_feed(None, "direct", 0, "ARP packets"))
        self.assertEqual(v.status, WARN)
        self.assertIn("needs root", v.summary)


def _answer(value):
    """Wrap a plain value so a stub method can stand in for a coroutine."""
    async def _coro():
        return value
    return _coro()


async def prot_verify(prot, helper):
    prot._helper = helper
    return await prot.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
