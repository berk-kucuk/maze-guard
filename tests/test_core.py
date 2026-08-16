"""
Unit tests for the detection, scoring and firewall logic.

No root, no network, no real firewall: everything here runs against injected
packets and a stub helper, so it can run anywhere.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import asyncio
import os
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from maze.core.events import Event, EventBus, EventType, ThreatLevel  # noqa: E402
from maze.core.incident import IncidentStore                # noqa: E402
from maze.detection.anomaly import AnomalyDetector                    # noqa: E402
from maze.protection.firewall import FirewallManager                  # noqa: E402
from maze.protection.port_scanner import PortScanDetector, _classify  # noqa: E402


def run(coro):
    return asyncio.run(coro)


class CollectingBus(EventBus):
    def __init__(self):
        super().__init__()
        self.events: list[Event] = []
        self.subscribe_all(self._collect)

    async def _collect(self, event: Event) -> None:
        self.events.append(event)

    def of_type(self, event_type: EventType) -> list[Event]:
        return [e for e in self.events if e.type == event_type]


# ── TCP flag classification ──────────────────────────────────────────────────

class TestFlagClassification(unittest.TestCase):
    def test_normal_traffic_is_not_a_technique(self):
        for flags in ("S", "SA", "PA", "A", "FA", "RA", "R"):
            self.assertEqual(_classify(flags), "", f"{flags} misread as stealth")

    def test_stealth_flags_are_named(self):
        self.assertEqual(_classify(""), "null_scan")
        self.assertEqual(_classify("F"), "fin_scan")
        self.assertEqual(_classify("FPU"), "xmas_scan")


# ── port scan detection ──────────────────────────────────────────────────────

class TestPortScanDetector(unittest.TestCase):
    def _detector(self, bus, threshold=25):
        det = PortScanDetector("lo", threshold=threshold)
        det._bus = bus
        det._own_ips = {"10.0.0.1"}
        return det

    def test_breadth_escalates_from_suspicious_to_dangerous(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for port in range(2000, 2100):
                await det._process("10.0.0.99", port, "S", "10.0.0.1")
        run(scenario())

        scans = bus.of_type(EventType.PORT_SCAN)
        self.assertEqual([e.level for e in scans],
                         [ThreatLevel.SUSPICIOUS, ThreatLevel.DANGEROUS])
        self.assertEqual(scans[-1].data["technique"], "syn_scan")
        self.assertGreaterEqual(scans[-1].data["unique_ports"], 75)

    def test_heavy_traffic_to_one_port_is_not_a_scan(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for _ in range(500):
                await det._process("10.0.0.5", 443, "S", "10.0.0.1")
        run(scenario())
        self.assertEqual(bus.of_type(EventType.PORT_SCAN), [])

    def test_own_and_whitelisted_traffic_is_ignored(self):
        bus = CollectingBus()
        det = self._detector(bus)
        det._whitelist = {"10.0.0.7"}

        async def scenario():
            for port in range(3000, 3100):
                await det._process("10.0.0.1", port, "S", "10.0.0.1")
                await det._process("10.0.0.7", port, "S", "10.0.0.1")
        run(scenario())
        self.assertEqual(bus.events, [])

    def test_stealth_scan_needs_no_volume(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for port in (21, 25, 139, 445):
                await det._process("10.0.0.66", port, "FPU", "10.0.0.1")
        run(scenario())

        stealth = bus.of_type(EventType.STEALTH_SCAN)
        self.assertEqual(len(stealth), 1)
        self.assertEqual(stealth[0].level, ThreatLevel.DANGEROUS)
        self.assertEqual(stealth[0].data["technique"], "xmas_scan")

    def test_one_stray_odd_packet_does_not_alert(self):
        bus = CollectingBus()
        det = self._detector(bus)
        run(det._process("10.0.0.66", 80, "F", "10.0.0.1"))
        self.assertEqual(bus.events, [])

    def test_evidence_is_retained_for_the_dossier(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for port in range(4000, 4040):
                await det._process("10.0.0.42", port, "S", "10.0.0.1")
        run(scenario())

        ev = det.evidence("10.0.0.42")
        self.assertEqual(ev["unique_ports"], 40)
        self.assertEqual(ev["packets"], 40)
        self.assertIn("syn_scan", ev["techniques"])


# ── anomaly / correlation ────────────────────────────────────────────────────

class TestAnomalyDetector(unittest.TestCase):
    def _detector(self, bus):
        det = AnomalyDetector("lo")
        det._bus = bus
        return det

    def test_arp_sweep_is_reported(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for i in range(25):
                await det._on_packet({"event": "arp", "op": 1, "src": "10.0.0.99",
                                      "mac": "aa:bb:cc:dd:ee:01",
                                      "dst": f"10.0.0.{i}"})
        run(scenario())
        self.assertEqual(len(bus.of_type(EventType.ARP_SCAN)), 1)

    def test_a_few_arp_requests_are_normal(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for i in range(5):
                await det._on_packet({"event": "arp", "op": 1, "src": "10.0.0.99",
                                      "mac": "aa:bb:cc:dd:ee:01",
                                      "dst": f"10.0.0.{i}"})
        run(scenario())
        self.assertEqual(bus.events, [])

    def test_one_mac_claiming_many_ips_flags_poisoning(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for i in range(6):
                await det._on_packet({"event": "arp", "op": 2,
                                      "src": f"10.0.0.{10 + i}",
                                      "mac": "aa:bb:cc:dd:ee:01", "dst": "10.0.0.1"})
        run(scenario())
        anomalies = bus.of_type(EventType.ANOMALY)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].data["technique"], "arp_poisoning")

    def test_second_dhcp_server_is_dangerous(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            await det._on_packet({"event": "dhcp", "src": "10.0.0.1",
                                  "server": "10.0.0.1", "mtype": 2})
            await det._on_packet({"event": "dhcp", "src": "10.0.0.99",
                                  "server": "10.0.0.99", "mtype": 2})
        run(scenario())
        rogue = bus.of_type(EventType.ROGUE_DHCP)
        self.assertEqual(len(rogue), 1)
        self.assertEqual(rogue[0].level, ThreatLevel.DANGEROUS)

    def test_single_dhcp_server_is_silent(self):
        bus = CollectingBus()
        det = self._detector(bus)

        async def scenario():
            for _ in range(4):
                await det._on_packet({"event": "dhcp", "src": "10.0.0.1",
                                      "server": "10.0.0.1", "mtype": 2})
        run(scenario())
        self.assertEqual(bus.events, [])

    def test_two_techniques_from_one_source_form_a_chain(self):
        bus = CollectingBus()
        det = self._detector(bus)
        bus.subscribe_all(det._on_event)

        async def scenario():
            await bus.emit(Event(type=EventType.PORT_SCAN,
                                 level=ThreatLevel.DANGEROUS,
                                 message="scan", data={"src": "10.0.0.99"}))
            await bus.emit(Event(type=EventType.ARP_SPOOF,
                                 level=ThreatLevel.DANGEROUS,
                                 message="spoof", data={"ip": "10.0.0.99"}))
        run(scenario())

        chains = bus.of_type(EventType.ATTACK_CHAIN)
        self.assertEqual(len(chains), 1)
        self.assertEqual(sorted(chains[0].data["stages"]),
                         ["arp_spoof", "port_scan"])

    def test_unrelated_sources_do_not_form_a_chain(self):
        bus = CollectingBus()
        det = self._detector(bus)
        bus.subscribe_all(det._on_event)

        async def scenario():
            await bus.emit(Event(type=EventType.PORT_SCAN,
                                 level=ThreatLevel.DANGEROUS,
                                 message="scan", data={"src": "10.0.0.98"}))
            await bus.emit(Event(type=EventType.ARP_SPOOF,
                                 level=ThreatLevel.DANGEROUS,
                                 message="spoof", data={"ip": "10.0.0.99"}))
        run(scenario())
        self.assertEqual(bus.of_type(EventType.ATTACK_CHAIN), [])


# ── incident store ───────────────────────────────────────────────────────────

class TestIncidentStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = IncidentStore(data_dir=Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def _scan_event(self, ip="10.0.0.99"):
        return Event(type=EventType.PORT_SCAN, level=ThreatLevel.DANGEROUS,
                     message="scan", data={"src": ip, "ports": [22, 80],
                                           "packets": 10,
                                           "technique": "syn_scan"})

    def test_event_without_a_source_is_not_filed(self):
        self.assertIsNone(self.store.record(Event(
            type=EventType.MODULE_TOGGLED, level=ThreatLevel.SAFE,
            message="toggled", data={"key": "tls"})))

    def test_severity_rises_with_distinct_techniques(self):
        att = self.store.record(self._scan_event())
        self.assertEqual(att.severity, "medium")
        att = self.store.record(Event(
            type=EventType.ARP_SPOOF, level=ThreatLevel.DANGEROUS,
            message="spoof", data={"ip": "10.0.0.99"}))
        self.assertEqual(att.severity, "high")

    def test_repeats_of_one_technique_count_for_less(self):
        first = self.store.record(self._scan_event()).score()
        for _ in range(5):
            self.store.record(self._scan_event())
        repeated = self.store.get("10.0.0.99").score()
        self.assertGreater(repeated, first)
        self.assertLess(repeated, first * 3)

    def test_score_decays_while_a_source_is_quiet(self):
        att = self.store.record(self._scan_event())
        fresh = att.score()
        att.scored_at = datetime.now() - timedelta(minutes=60)
        self.assertAlmostEqual(att.score(), fresh / 4, delta=1.0)

    def test_recon_enriches_the_dossier(self):
        self.store.record(self._scan_event())
        self.store.attach_recon("10.0.0.99", {
            "mac": "aa:bb:cc:dd:ee:01", "vendor": "VMware",
            "os_hint": "Linux / Unix", "open_ports": [[4444, "Metasploit?"]],
            "risk_score": 40, "findings": ["port 4444 open"],
        })
        att = self.store.get("10.0.0.99")
        self.assertEqual(att.vendor, "VMware")
        self.assertEqual(att.open_ports, [[4444, "Metasploit?"]])

    def test_dossiers_survive_a_restart(self):
        self.store.record(self._scan_event())
        self.store.mark_blocked("10.0.0.99")
        reopened = IncidentStore(data_dir=Path(self._tmp.name))
        att = reopened.get("10.0.0.99")
        self.assertIsNotNone(att)
        self.assertTrue(att.blocked)
        self.assertIn("syn_scan", att.techniques)

    def test_evidence_journal_is_appended(self):
        self.store.record(self._scan_event())
        self.assertTrue(self.store.journal_path.exists())
        self.assertIn("10.0.0.99",
                      self.store.journal_path.read_text(encoding="utf-8"))

    def test_report_contains_the_essentials(self):
        self.store.record(self._scan_event())
        report = self.store.get("10.0.0.99").report()
        for expected in ("10.0.0.99", "Techniques", "Timeline", "Severity"):
            self.assertIn(expected, report)

    def test_export_writes_a_file(self):
        self.store.record(self._scan_event())
        out = Path(self._tmp.name) / "report.md"
        self.assertTrue(self.store.export_report("10.0.0.99", out))
        self.assertIn("incident report", out.read_text(encoding="utf-8"))


# ── firewall manager ─────────────────────────────────────────────────────────

class StubHelper:
    def __init__(self, running=True, target="default", zone="public"):
        self.state = {"installed": True, "running": running, "enabled": True,
                      "zone": zone, "target": target, "panic": False}
        self.calls: list[list[str]] = []
        self.accept = True

    def is_connected(self):
        return True

    async def fw_state(self):
        return dict(self.state)

    async def fw_list(self):
        return {"ips": [], "ports_tcp": [], "ports_udp": []}

    async def fw_list_all(self):
        return f"{self.state['zone']} (default, active)\n"

    async def fw_cmd(self, args):
        self.calls.append(args)
        if not self.accept:
            return False
        for arg in args:
            if arg == "--set-target=DROP":
                self.state["target"] = "DROP"
            elif arg == "--set-target=default":
                self.state["target"] = "default"
        return True

    async def fw_service(self, action):
        self.calls.append(["systemctl", action])
        if not self.accept:
            return False, "unit failed"
        if action == "start":
            self.state["running"] = True
        elif action == "stop":
            self.state["running"] = False
        return True, ""


class DisconnectedHelper(StubHelper):
    def is_connected(self):
        return False


class TestFirewallManager(unittest.TestCase):
    def _manager(self, helper):
        fw = FirewallManager()
        run(fw.start(None, helper=helper))
        return fw

    def test_state_reflects_the_backend(self):
        fw = self._manager(StubHelper(running=True, target="DROP", zone="home"))
        self.assertTrue(fw.state.running)
        self.assertEqual(fw.state.zone, "home")
        self.assertTrue(fw.state.incoming_blocked)

    def test_shield_toggles_the_real_zone_not_a_hardcoded_one(self):
        helper = StubHelper(zone="home", target="default")
        fw = self._manager(helper)
        self.assertTrue(run(fw.enable_incoming_block()))
        self.assertTrue(fw.state.incoming_blocked)
        self.assertTrue(run(fw.disable_incoming_block()))
        self.assertFalse(fw.state.incoming_blocked)
        for call in helper.calls:
            if "--zone" in call:
                self.assertEqual(call[call.index("--zone") + 1], "home")

    def test_disable_shield_without_prior_init_still_uses_the_right_zone(self):
        helper = StubHelper(zone="internal", target="DROP")
        fw = FirewallManager()          # no start(), nothing cached
        fw._helper = helper
        self.assertTrue(run(fw.disable_incoming_block()))
        zone_calls = [c[c.index("--zone") + 1] for c in helper.calls
                      if "--zone" in c]
        self.assertEqual(set(zone_calls), {"internal"})

    def test_backend_can_be_started_and_stopped(self):
        helper = StubHelper(running=False)
        fw = self._manager(helper)
        self.assertFalse(fw.state.running)
        self.assertTrue(run(fw.enable_firewall()))
        self.assertTrue(fw.state.running)
        self.assertTrue(run(fw.disable_firewall()))
        self.assertFalse(fw.state.running)

    def test_failures_are_reported_not_swallowed(self):
        helper = StubHelper(running=False)
        helper.accept = False
        fw = self._manager(helper)
        self.assertFalse(run(fw.enable_firewall()))
        self.assertTrue(fw.last_error)

    def test_without_the_helper_nothing_claims_success(self):
        fw = self._manager(DisconnectedHelper())
        self.assertFalse(fw.state.installed)
        self.assertFalse(run(fw.enable_firewall()))
        self.assertFalse(run(fw.block_ip("1.2.3.4")))
        self.assertFalse(run(fw.enable_incoming_block()))
        self.assertIn("helper", fw.last_error)

    def test_block_rules_are_family_correct_and_logged(self):
        helper = StubHelper()
        fw = self._manager(helper)
        run(fw.block_ip("192.168.1.5"))
        run(fw.block_ip("fe80::1"))
        rules = [c[-1] for c in helper.calls if "--add-rich-rule" in c]
        self.assertTrue(rules[0].startswith("rule family=ipv4"))
        self.assertTrue(rules[1].startswith("rule family=ipv6"))
        self.assertIn("log prefix=MAZE-BLOCK", rules[0])


# ── helper-side allowlist ────────────────────────────────────────────────────

class TestHelperRuleAllowlist(unittest.TestCase):
    """The helper runs as root; whatever it accepts is what a maze-group
    member can do to the firewall. These are the boundaries."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        path = Path(__file__).resolve().parent.parent / "maze" / "helper.py"
        spec = importlib.util.spec_from_file_location("maze_helper_mod", path)
        cls.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.helper)

    def _allowed(self, rule: str) -> bool:
        return any(rx.match(rule) for rx in self.helper._FWC_RULE_RES)

    def test_maze_block_rules_are_accepted(self):
        for rule in (
            "rule family=ipv4 source address=192.168.1.5 drop",
            "rule family=ipv4 source address=192.168.1.5 "
            "log prefix=MAZE-BLOCK level=info limit value=3/m drop",
            "rule family=ipv6 source address=fe80::1 drop",
            "rule family=ipv4 port port=23 protocol=tcp drop",
        ):
            self.assertTrue(self._allowed(rule), rule)

    def test_dangerous_rules_are_rejected(self):
        for rule in (
            "rule family=ipv4 source address=0.0.0.0/0 drop",
            "rule family=ipv6 source address=::/0 drop",
            "rule family=ipv4 source address=1.2.3.4 accept",
            "rule family=ipv4 source address=1.2.3.4 drop accept",
            "rule family=ipv4 source address=1.2.3.4 masquerade",
            "rule family=ipv4 source address=1.2.3.4 "
            "forward-port port=22 protocol=tcp to-port=2222",
            "rule family=ipv4 source address=1.2.3.4 "
            "log prefix=EVIL level=info limit value=3/m drop",
            "rule family=ipv4 source address=1.2.3.4 "
            "log prefix=MAZE-X level=emerg limit value=9999/s drop",
        ):
            self.assertFalse(self._allowed(rule), rule)

    def test_only_curated_flags_pass(self):
        for flag in ("--panic-on", "--direct", "--remove-service=ssh",
                     "--add-service=ssh", "--set-target=ACCEPT"):
            self.assertNotIn(flag, self.helper._FWC_SAFE_FLAGS)

    def test_default_zone_cannot_be_switched(self):
        """`--set-default-zone trusted` is a one-line firewall bypass available
        to anything running as the desktop user. No feature needs it."""
        self.assertNotIn("--set-default-zone", self.helper._FWC_SAFE_FLAGS)

    def test_state_changing_commands_are_audited(self):
        helper = self.helper
        logged: list[str] = []

        class FakeWriter:
            def get_extra_info(self, _):
                raise OSError("no socket in this test")

        async def spy(args, timeout=10.0):
            return helper._Completed(returncode=0)

        async def up():
            return True

        original = (helper._audit, helper._run, helper._firewalld_active)
        helper._audit = lambda w, what: logged.append(what)
        helper._run, helper._firewalld_active = spy, up
        try:
            asyncio.run(helper._dispatch(
                {"cmd": "fw_service", "action": "stop", "id": 1}, FakeWriter()))
            asyncio.run(helper._dispatch(
                {"cmd": "fw_service", "action": "is-active", "id": 2}, FakeWriter()))
            asyncio.run(helper._dispatch({"cmd": "ping", "id": 3}, FakeWriter()))
        finally:
            helper._audit, helper._run, helper._firewalld_active = original

        # The destructive one is recorded; queries and pings are not.
        self.assertEqual(logged, ["fw_service stop firewalld"])

    def test_service_control_is_limited_to_the_firewall_unit(self):
        self.assertEqual(self.helper._FW_UNIT, "firewalld")
        self.assertNotIn("sshd", self.helper._SVC_ALLOWED)

    def test_packet_handler_emits_the_expected_contract(self):
        """The capture thread is the one piece the detectors cannot work
        without, and it runs as root where nothing else can reach it. Drive it
        with crafted packets and assert what it publishes."""
        try:
            import scapy.all as sa
            from scapy.all import ARP, BOOTP, DHCP, Ether, ICMP, IP, TCP, UDP
        except Exception:
            self.skipTest("scapy is not installed")

        pushed: list[dict] = []
        original_push, original_sniff = self.helper._push, sa.sniff
        self.helper._push = pushed.append
        packets = [
            Ether() / ARP(op=1, psrc="10.0.0.9", hwsrc="aa:bb:cc:00:00:01",
                          pdst="10.0.0.5"),
            Ether() / IP(src="10.0.0.9", dst="10.0.0.5")
            / TCP(dport=22, flags="S"),
            Ether() / IP(src="10.0.0.9", dst="10.0.0.5")
            / TCP(dport=139, flags="FPU"),
            Ether() / IP(src="10.0.0.9", dst="10.0.0.5") / ICMP(type=8),
            Ether() / IP(src="10.0.0.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68) / BOOTP()
            / DHCP(options=[("message-type", "offer"),
                            ("server_id", "10.0.0.1"), "end"]),
            # Ours: must never be reported as somebody else's activity.
            Ether() / IP(src="10.0.0.5", dst="1.1.1.1") / TCP(dport=443, flags="S"),
        ]
        # A wire-parsed DHCP packet numbers its message-type instead of naming
        # it; both encodings have to resolve to the same event.
        packets.append(Ether(bytes(packets[4])))
        try:
            sa.sniff = lambda **kw: [kw["prn"](p) for p in packets]
            self.helper._get_iface_ips = lambda iface: {"10.0.0.5"}
            self.helper._sniff_once("lo", self.helper._PushLimiter(400), 1)
        finally:
            self.helper._push, sa.sniff = original_push, original_sniff

        kinds = [p["event"] for p in pushed]
        self.assertEqual(kinds, ["arp", "tcp", "tcp", "icmp", "dhcp", "dhcp"])
        self.assertEqual(pushed[0]["op"], 1)
        self.assertEqual(pushed[1]["flags"], "S")
        self.assertEqual(pushed[2]["flags"], "FPU")
        self.assertEqual(pushed[4]["mtype"], 2)
        self.assertEqual(pushed[5]["mtype"], 2)
        self.assertTrue(all(p.get("src") != "10.0.0.5" for p in pushed))

    def test_slow_command_cannot_freeze_the_helper(self):
        """A hung external command must not take the daemon down with it.

        This is not hypothetical: with firewalld stopped, `firewall-cmd` waits
        on D-Bus activation, and the GUI polls the rule list on a timer. Run
        straight from the coroutine, those calls wedged the event loop so
        completely that even `ping` went unanswered — the firewall could be
        switched off from the UI and then never switched back on.
        """
        helper = self.helper
        original = helper.subprocess.run

        def slow_run(args, **kwargs):
            import time as _t
            _t.sleep(1.5)
            raise AssertionError("should have been abandoned before finishing")

        async def scenario():
            helper.subprocess.run = slow_run
            try:
                started = asyncio.get_running_loop().time()
                slow = asyncio.create_task(
                    helper._run(["sleep", "2"], timeout=0.3))
                # While that is outstanding, an unrelated request must still be
                # served promptly — that is the whole point.
                pong = await asyncio.wait_for(
                    helper._dispatch({"cmd": "ping", "id": 1}, None), timeout=1.0)
                result = await slow
                return pong, result, asyncio.get_running_loop().time() - started
            finally:
                helper.subprocess.run = original

        pong, result, elapsed = asyncio.run(scenario())
        self.assertTrue(pong["ok"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out", result.stderr)
        self.assertLess(elapsed, 4.0, "the helper waited for the hung command")

    def test_firewall_commands_are_skipped_when_firewalld_is_down(self):
        helper = self.helper
        original = helper._firewalld_active
        saved_audit, helper._audit = helper._audit, lambda w, s: None
        ran: list[list[str]] = []

        async def scenario():
            async def down():
                return False

            async def spy(args, timeout=10.0):
                ran.append(args)
                return helper._Completed(returncode=0)

            helper._firewalld_active = down
            original_run, helper._run = helper._run, spy
            try:
                return (await helper._dispatch({"cmd": "fw_list_all", "id": 1}, None),
                        await helper._dispatch(
                            {"cmd": "fw_cmd", "id": 2,
                             "args": ["firewall-cmd", "--reload"]}, None))
            finally:
                helper._firewalld_active = original
                helper._run = original_run
                helper._audit = saved_audit

        list_all, fw_cmd = asyncio.run(scenario())
        self.assertEqual(ran, [], "firewall-cmd was invoked against a dead firewalld")
        self.assertIn("not running", list_all.get("err", ""))
        self.assertFalse(fw_cmd["ok"])
        self.assertIn("not running", fw_cmd.get("err", ""))

    # ── consent for protection-disabling requests ─────────────────────────

    def _authz_harness(self, granted: bool):
        """Drive _dispatch with polkit stubbed to grant or refuse."""
        helper = self.helper
        ran: list[list[str]] = []

        async def spy(args, timeout=10.0):
            ran.append(args)
            return helper._Completed(returncode=0)

        async def up():
            return True

        async def verdict(writer, what):
            return (True, "") if granted else (False, "authorisation was declined")

        saved = (helper._run, helper._firewalld_active,
                 helper._authorized, helper._audit)
        helper._run, helper._firewalld_active = spy, up
        helper._authorized, helper._audit = verdict, lambda w, s: None

        def restore():
            (helper._run, helper._firewalld_active,
             helper._authorized, helper._audit) = saved

        return ran, restore

    def test_stopping_the_firewall_requires_consent(self):
        ran, restore = self._authz_harness(granted=False)
        try:
            resp = asyncio.run(self.helper._dispatch(
                {"cmd": "fw_service", "action": "stop", "id": 1}, None))
        finally:
            restore()
        self.assertFalse(resp["ok"])
        self.assertEqual(ran, [], "the firewall was stopped without consent")

    def test_granted_consent_lets_the_stop_through(self):
        ran, restore = self._authz_harness(granted=True)
        try:
            resp = asyncio.run(self.helper._dispatch(
                {"cmd": "fw_service", "action": "stop", "id": 1}, None))
        finally:
            restore()
        self.assertTrue(resp["ok"])
        self.assertEqual(ran, [["systemctl", "stop", "firewalld"]])

    def test_lowering_the_shield_and_unblocking_require_consent(self):
        for args in (["firewall-cmd", "--permanent", "--zone", "public",
                      "--set-target=default"],
                     ["firewall-cmd", "--permanent", "--zone", "public",
                      "--remove-rich-rule",
                      "rule family=ipv4 source address=10.0.0.9 drop"]):
            ran, restore = self._authz_harness(granted=False)
            try:
                resp = asyncio.run(self.helper._dispatch(
                    {"cmd": "fw_cmd", "args": args, "id": 1}, None))
            finally:
                restore()
            self.assertFalse(resp["ok"], args)
            self.assertEqual(ran, [], f"ran without consent: {args}")

    def test_protective_actions_are_never_gated(self):
        """Blocking an attacker, raising the shield and starting the firewall
        must stay friction-free — including the automatic block, which has no
        user present to answer a prompt."""
        for req in (
            {"cmd": "fw_cmd", "id": 1,
             "args": ["firewall-cmd", "--permanent", "--zone", "public",
                      "--add-rich-rule",
                      "rule family=ipv4 source address=10.0.0.9 drop"]},
            {"cmd": "fw_cmd", "id": 2,
             "args": ["firewall-cmd", "--permanent", "--zone", "public",
                      "--set-target=DROP"]},
            {"cmd": "fw_service", "action": "start", "id": 3},
            {"cmd": "fw_cmd", "id": 4, "args": ["firewall-cmd", "--reload"]},
        ):
            # Consent is stubbed to REFUSE; these must succeed anyway, which
            # proves they never consult it.
            ran, restore = self._authz_harness(granted=False)
            try:
                resp = asyncio.run(self.helper._dispatch(req, None))
            finally:
                restore()
            self.assertTrue(resp["ok"], req)
            self.assertTrue(ran, f"never executed: {req}")

    def test_routine_cleanup_is_not_treated_as_a_downgrade(self):
        """Removing Maze Guard's own mDNS/NetBIOS port rules happens on every
        profile change. Prompting for a password there would put a dialog in
        front of an ordinary profile switch, and exposes the user to nothing."""
        needs = self.helper._needs_consent
        for proto, port in (("udp", 5353), ("udp", 137), ("udp", 138)):
            self.assertEqual(needs(
                ["firewall-cmd", "--permanent", "--remove-rich-rule",
                 f"rule family=ipv4 port port={port} protocol={proto} drop"]), "")
        self.assertEqual(needs(["firewall-cmd", "--reload"]), "")
        self.assertEqual(needs(["firewall-cmd", "--permanent", "--zone",
                                "public", "--set-target=DROP"]), "")

    def test_real_downgrades_are_recognised(self):
        needs = self.helper._needs_consent
        self.assertIn("shield", needs(["firewall-cmd", "--permanent", "--zone",
                                       "public", "--set-target=default"]))
        self.assertIn("attacker", needs(
            ["firewall-cmd", "--permanent", "--remove-rich-rule",
             "rule family=ipv4 source address=10.0.0.9 drop"]))

    def test_polkit_subject_is_pinned_against_pid_reuse(self):
        """A bare pid can be recycled between check and act; the subject must
        carry the process start time and uid too."""
        helper = self.helper
        calls: list[list[str]] = []

        async def spy(args, timeout=10.0):
            calls.append(args)
            return helper._Completed(returncode=0)

        saved_run, saved_cred = helper._run, helper._peer_cred
        saved_audit, helper._audit = helper._audit, lambda w, s: None
        helper._run = spy
        helper._peer_cred = lambda w: (4242, 1000)
        try:
            with unittest.mock.patch.object(helper, "_proc_start_time",
                                            return_value=99887766):
                ok, _ = asyncio.run(helper._authorized(None, "stop"))
        finally:
            helper._run, helper._peer_cred = saved_run, saved_cred
            helper._audit = saved_audit

        self.assertTrue(ok)
        self.assertIn("--process", calls[0])
        self.assertEqual(calls[0][calls[0].index("--process") + 1],
                         "4242,99887766,1000")
        self.assertIn("--allow-user-interaction", calls[0])

    def test_consent_is_denied_when_the_caller_cannot_be_identified(self):
        helper = self.helper
        saved = helper._peer_cred
        helper._peer_cred = lambda w: (-1, -1)
        try:
            ok, why = asyncio.run(helper._authorized(None, "stop"))
        finally:
            helper._peer_cred = saved
        self.assertFalse(ok)
        self.assertIn("identify", why)

    def test_push_limiter_caps_the_flood(self):
        limiter = self.helper._PushLimiter(5)
        allowed = sum(1 for _ in range(100) if limiter.allow())
        self.assertEqual(allowed, 5)

    def test_capture_filter_excludes_established_traffic(self):
        # An ACK-bearing packet belongs to a real conversation; admitting those
        # would push ordinary browsing through the whole detection pipeline.
        self.assertIn("tcp[tcpflags] & tcp-ack = 0", self.helper._SNIFF_BPF)


if __name__ == "__main__":
    unittest.main(verbosity=2)
