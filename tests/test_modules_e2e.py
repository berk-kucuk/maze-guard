"""
Every protection module, one at a time, through the engine.

Each module is started and stopped the way the Protection page does it, with
the real helper code serving it in-process against a simulated firewalld
(tests/support/fake_firewalld.py). The detection paths that had no end-to-end
coverage — ARP spoofing seen through the helper, untrusted programs — are
driven with synthetic input.

    ./venv/bin/python -m unittest tests.test_modules_e2e -v
"""
import asyncio
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")

from maze.core.events import Event, EventBus, EventType, ThreatLevel   # noqa: E402
from maze.core.verify import Verdict                                   # noqa: E402
from support.fake_firewalld import FakeFirewalld, InProcessHelper      # noqa: E402

# Every module key the Protection page lists, minus the two firewall rows
# that are not engine modules.
MODULE_KEYS = ("arp_watch", "rogue_ap", "dns_validate", "tls", "ssl_strip",
               "anomaly", "hostname", "service_blocker", "fingerprint",
               "port_scan", "process", "dns_leak", "firewall")


class _Cfg:
    interface = "lo"
    port_scan_threshold = 25
    whitelist_ips: list = []
    known_processes = ["firefox", "ssh"]
    auto_block = False
    profile = "home"


class _Collect(EventBus):
    def __init__(self):
        super().__init__()
        self.events: list[Event] = []

    async def emit(self, event):
        self.events.append(event)
        await super().emit(event)


async def _idle(*_a, **_k):
    """Stands in for loops that would reach the internet from a test."""
    await asyncio.Event().wait()


class ModuleLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = unittest.mock.patch.dict(os.environ, {"MAZE_DATA_DIR": self.tmp.name})
        self.env.start()
        # The stealth modules keep crash-recovery files next to their data.
        import maze.stealth.fingerprint as fp
        import maze.stealth.hostname_hide as hh
        self.files = [
            unittest.mock.patch.object(fp, "_STATE_FILE", Path(self.tmp.name) / "fp.json"),
            unittest.mock.patch.object(hh, "_STATE_FILE", Path(self.tmp.name) / "hh.json"),
            unittest.mock.patch.object(hh.HostnameHider, "_unit_exists",
                                       staticmethod(lambda: True)),
        ]
        for p in self.files:
            p.start()
        self.fw = FakeFirewalld()
        self.helper = InProcessHelper(self.fw)
        from maze.core.engine import MazeEngine
        self.engine = MazeEngine(_Cfg(), helper=self.helper)
        for key in ("tls", "dns_validate"):
            self.engine._modules[key]._monitor = _idle

    def tearDown(self):
        for p in reversed(self.files):
            p.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_every_module_starts_reports_and_stops_cleanly(self):
        async def go():
            failures = {}
            for key in MODULE_KEYS:
                await self.engine._start_module(key)
                if key not in self.engine._active:
                    failures[key] = self.engine.module_error(key)
                    continue
                detail = self.engine.module_detail(key)
                self.assertIsInstance(detail, str)
                await self.engine._stop_module(key)
                self.assertNotIn(key, self.engine._active)
            await self.engine.stop()
            return failures
        self.assertEqual(asyncio.run(go()), {})

    def test_every_self_test_answers_with_a_verdict(self):
        async def go():
            out = {}
            for key in ("arp_watch", "anomaly", "hostname", "service_blocker",
                        "fingerprint", "port_scan", "process", "dns_leak",
                        "fw_backend", "firewall"):
                out[key] = await self.engine.verify_module(key)
            await self.engine.stop()
            return out
        for key, verdict in asyncio.run(go()).items():
            self.assertIsInstance(verdict, Verdict, key)
            self.assertTrue(verdict.summary, key)
            # A stopped module's self-test must not blame the helper.
            self.assertNotIn("helper is not connected", verdict.summary, key)

    def test_stealth_modules_change_the_system_and_put_it_back(self):
        async def go():
            for key in ("hostname", "fingerprint", "service_blocker"):
                await self.engine._start_module(key)
            during = (dict(self.fw.units), dict(self.fw.sysctl), list(self.fw.rules))
            verdicts = {k: await self.engine.verify_module(k)
                        for k in ("hostname", "fingerprint", "service_blocker")}
            await self.engine.stop()
            return during, verdicts
        before = (dict(self.fw.units), dict(self.fw.sysctl), list(self.fw.rules))
        (units, sysctl, rules), verdicts = asyncio.run(go())
        self.assertFalse(units["avahi-daemon"])
        self.assertFalse(units["avahi-daemon.socket"])
        self.assertEqual(sysctl["net.ipv4.ip_default_ttl"], "128")
        self.assertEqual(sysctl["net.ipv4.tcp_timestamps"], "0")
        self.assertEqual(len(rules), 16)             # 8 ports × 2 families
        for key, verdict in verdicts.items():
            self.assertEqual(verdict.status, "pass", f"{key}: {verdict.summary}")
        self.assertEqual((dict(self.fw.units), dict(self.fw.sysctl), list(self.fw.rules)),
                         before)

    def test_profile_switches_do_not_multiply_listeners(self):
        from maze.core.profile import Profile

        async def go():
            for profile in (Profile.HOME, Profile.PARANOID, Profile.PUBLIC,
                            Profile.HOME):
                await self.engine.apply_profile(profile)
            callbacks = list(self.helper._event_cbs)
            catch_all = list(self.engine.bus._catch_all)
            await self.engine.stop()
            return callbacks, catch_all
        callbacks, catch_all = asyncio.run(go())
        self.assertEqual(len(callbacks), len(set(callbacks)))
        self.assertEqual(len(catch_all), len(set(catch_all)))
        # arp_watch, anomaly, port_scan and dns_leak listen to the capture.
        self.assertEqual(len(callbacks), 4)


class ARPSpoofThroughHelperTests(unittest.TestCase):
    """The helper path, end to end: packets in, ARP_SPOOF out."""

    def _watcher(self):
        from maze.detection import arp_watch
        bus = _Collect()
        helper = InProcessHelper(FakeFirewalld())
        watcher = arp_watch.ARPWatcher("lo")
        patches = [
            unittest.mock.patch.object(arp_watch, "_get_own_ips", lambda _i: {"192.168.1.101"}),
            unittest.mock.patch.object(arp_watch, "_get_gateway_info",
                                       lambda _i=None: ("192.168.1.1", "aa:aa:aa:aa:aa:01")),
            unittest.mock.patch.object(arp_watch, "link_epoch", lambda _i: (1,)),
        ]
        return arp_watch, watcher, bus, helper, patches

    def _run(self, steps, kernel_mac):
        arp_watch, watcher, bus, helper, patches = self._watcher()

        async def go():
            for p in patches:
                p.start()
            try:
                await watcher.start(bus, helper=helper)
                with unittest.mock.patch.object(arp_watch, "_kernel_mac", kernel_mac):
                    for msg in steps:
                        await helper.push(msg)
                        await asyncio.sleep(0)
                await watcher.stop()
            finally:
                for p in reversed(patches):
                    p.stop()
        asyncio.run(go())
        return watcher, bus.events

    @staticmethod
    def arp(ip, mac, op=2):
        return {"event": "arp", "op": op, "src": ip, "mac": mac, "dst": "192.168.1.101"}

    def test_a_gateway_impersonation_is_dangerous(self):
        _, events = self._run(
            [self.arp("192.168.1.1", "aa:aa:aa:aa:aa:01"),
             self.arp("192.168.1.1", "ee:ee:ee:ee:ee:66")],
            kernel_mac=lambda _ip: "ee:ee:ee:ee:ee:66")
        spoof = [e for e in events if e.type == EventType.ARP_SPOOF]
        self.assertEqual(len(spoof), 1)
        self.assertEqual(spoof[0].level, ThreatLevel.DANGEROUS)
        self.assertIn("ee:ee:ee:ee:ee:66", spoof[0].message)

    def test_two_live_owners_of_one_address_is_dangerous(self):
        _, events = self._run(
            [self.arp("192.168.1.50", "aa:aa:aa:aa:aa:50"),
             self.arp("192.168.1.50", "ee:ee:ee:ee:ee:66")],
            kernel_mac=lambda _ip: "ee:ee:ee:ee:ee:66")
        self.assertEqual([e.level for e in events if e.type == EventType.ARP_SPOOF],
                         [ThreatLevel.DANGEROUS])

    def test_relay_noise_the_kernel_never_accepts_is_silent(self):
        _, events = self._run(
            [self.arp("192.168.1.50", "aa:aa:aa:aa:aa:50"),
             self.arp("192.168.1.50", "ee:ee:ee:ee:ee:66")],
            kernel_mac=lambda _ip: "aa:aa:aa:aa:aa:50")
        self.assertFalse([e for e in events if e.type == EventType.ARP_SPOOF])

    def test_a_reused_lease_is_only_noted(self):
        from maze.detection import arp_watch
        arp_mod, watcher, bus, helper, patches = self._watcher()

        async def go():
            for p in patches:
                p.start()
            try:
                await watcher.start(bus, helper=helper)
                await helper.push(self.arp("192.168.1.60", "aa:aa:aa:aa:aa:60"))
                # The previous owner has been silent for longer than the window.
                watcher._mac_seen["aa:aa:aa:aa:aa:60"] -= arp_watch._OLD_MAC_ALIVE_WINDOW + 5
                with unittest.mock.patch.object(arp_mod, "_kernel_mac",
                                                lambda _ip: "bb:bb:bb:bb:bb:61"):
                    await helper.push(self.arp("192.168.1.60", "bb:bb:bb:bb:bb:61"))
                await watcher.stop()
            finally:
                for p in reversed(patches):
                    p.stop()
        asyncio.run(go())
        kinds = [(e.type, e.level) for e in bus.events if e.type != EventType.DEVICE_FOUND]
        self.assertEqual(kinds, [(EventType.IP_MOVED, ThreatLevel.SUSPICIOUS)])

    def test_own_addresses_and_probes_are_ignored(self):
        watcher, events = self._run(
            [self.arp("192.168.1.101", "11:11:11:11:11:11"),
             self.arp("0.0.0.0", "22:22:22:22:22:22", op=1)],
            kernel_mac=lambda _ip: None)
        self.assertEqual(events, [])
        self.assertEqual(watcher.devices, {})


class ProcessMonitorTests(unittest.TestCase):
    def _monitor(self):
        from maze.protection.process_map import ProcessNetworkMonitor
        bus = _Collect()
        mon = ProcessNetworkMonitor({"firefox", "bitwarden"}, whitelist=["10.9.0.0/16"])
        mon._bus = bus
        return mon, bus

    @staticmethod
    def conn(process, ip, port, cmdline=""):
        from maze.protection.process_map import Connection
        return Connection(pid=42, process=process, local_addr="192.168.1.101:50000",
                          remote_addr=f"{ip}:{port}", remote_ip=ip, remote_port=port,
                          cmdline=cmdline)

    def test_an_untrusted_program_on_an_odd_port_is_reported_once(self):
        mon, bus = self._monitor()
        conns = [self.conn("backdoor", "45.33.32.156", 4444)]
        self.assertEqual(asyncio.run(mon.check(conns)), 1)
        self.assertEqual(asyncio.run(mon.check(conns)), 0)          # deduplicated
        self.assertEqual(bus.events[0].type, EventType.UNKNOWN_PROCESS)
        self.assertIn("backdoor", bus.events[0].message)

    def test_trusted_programs_web_ports_and_ignored_addresses_are_quiet(self):
        mon, bus = self._monitor()
        conns = [self.conn("firefox", "1.2.3.4", 9999),
                 self.conn("electron", "1.2.3.4", 9999,
                           cmdline="/usr/lib/bitwarden/app.asar"),
                 self.conn("curl", "1.2.3.4", 443),
                 self.conn("backdoor", "10.9.1.1", 4444)]
        self.assertEqual(asyncio.run(mon.check(conns)), 0)
        self.assertEqual(bus.events, [])

    def test_the_watch_survives_a_failed_scan(self):
        mon, bus = self._monitor()
        calls = {"n": 0}

        async def flaky_snapshot():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("helper restarted")
            return [self.conn("backdoor", "45.33.32.156", 4444)]
        mon.snapshot = flaky_snapshot
        real_sleep = asyncio.sleep

        async def go():
            with unittest.mock.patch("maze.protection.process_map.asyncio.sleep",
                                     lambda _d: real_sleep(0)):
                task = asyncio.create_task(mon._monitor())
                for _ in range(50):
                    await real_sleep(0)
                    if bus.events:
                        break
                task.cancel()
        asyncio.run(go())
        self.assertGreaterEqual(calls["n"], 2)
        self.assertEqual(len(bus.events), 1)


if __name__ == "__main__":
    unittest.main()
