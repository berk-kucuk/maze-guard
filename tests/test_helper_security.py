"""
Security tests for the privileged helper (maze/helper.py).

The helper runs as root and listens to every process of the desktop user, so
its request handling is the boundary between "a program the user ran" and
"root". These tests pin down that boundary:

  * each specific hole that was found and closed stays closed;
  * a fuzzer throws thousands of malformed and hostile requests at the real
    dispatcher and checks three invariants on every one — it never raises,
    it never executes anything outside the allow-list, and nothing that needs
    the user's consent ever runs without asking.

    ./venv/bin/python -m unittest tests.test_helper_security -v
"""
import asyncio
import ipaddress
import json
import os
import random
import socket
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")

import maze.helper as H                                         # noqa: E402

GATEWAY, GATEWAY_MAC, DNS = "192.168.1.1", "ac:15:a2:52:45:0b", "192.168.1.53"
PORT_RULE = "rule family=ipv4 port port=5353 protocol=udp drop"
ADDR_RULE = "rule family=ipv4 source address=192.168.1.66 drop"
MAC_RULE = "rule source mac=de:ad:be:ef:00:01 drop"


class Harness:
    """Run _dispatch with every side effect recorded instead of performed."""

    def __init__(self, consent: bool = True, peer_uid: int = 1000):
        self.ran: list[list[str]] = []
        self.consent_asked: list[tuple[str, str]] = []
        self.consent = consent
        self.peer_uid = peer_uid

    async def _run(self, args, timeout=10.0):
        self.ran.append(list(args))
        if args[:2] == ["systemctl", "is-active"]:
            return H._Completed(0, "active")
        return H._Completed(0, "")

    async def _authorized(self, _writer, what, action=H._POLKIT_ACTION):
        self.consent_asked.append((what, action))
        return (True, "") if self.consent else (False, "declined")

    def dispatch(self, req):
        with unittest.mock.patch.object(H, "_run", self._run), \
             unittest.mock.patch.object(H, "_authorized", self._authorized), \
             unittest.mock.patch.object(H, "_audit", lambda *_a: None), \
             unittest.mock.patch.object(H, "_fw_unit_installed", lambda: True), \
             unittest.mock.patch.object(H, "_peer_uid", lambda _w: self.peer_uid), \
             unittest.mock.patch.object(H, "_default_gateways", lambda: {GATEWAY}), \
             unittest.mock.patch.object(H, "_nameservers", lambda: {DNS}), \
             unittest.mock.patch.object(H, "_gateway_macs", lambda _g: {GATEWAY_MAC}):
            H._fw_forget()
            return asyncio.run(H._dispatch(req, object()))

    def fw(self, *args):
        return self.dispatch({"cmd": "fw_cmd", "id": 1, "args": ["firewall-cmd", *args]})


# ── specific holes, each pinned ────────────────────────────────────────────────

class ConsentBypassTests(unittest.TestCase):
    def test_a_second_removal_cannot_ride_on_a_harmless_one(self):
        h = Harness(consent=False)
        resp = h.fw("--permanent", "--remove-rich-rule", PORT_RULE,
                    "--remove-rich-rule", ADDR_RULE)
        self.assertFalse(resp["ok"])
        self.assertEqual(h.ran, [])
        # And the consent check itself looks at every removal.
        self.assertIn("attacker", H._needs_consent(
            ["firewall-cmd", "--remove-rich-rule", PORT_RULE,
             "--remove-rich-rule", ADDR_RULE]))

    def test_removing_an_attacker_block_asks_and_a_refusal_holds(self):
        h = Harness(consent=False)
        for rule in (ADDR_RULE, MAC_RULE):
            resp = h.fw("--permanent", "--zone", "public", "--remove-rich-rule", rule)
            self.assertFalse(resp["ok"], rule)
        self.assertEqual(h.ran, [])
        self.assertEqual(len(h.consent_asked), 2)

    def test_lowering_the_shield_asks(self):
        h = Harness(consent=False)
        self.assertFalse(h.fw("--permanent", "--zone", "public",
                              "--set-target=default")["ok"])
        self.assertEqual(h.ran, [])

    def test_routine_protection_never_asks(self):
        h = Harness(consent=False)
        for args in (("--permanent", "--zone", "public", "--add-rich-rule", ADDR_RULE),
                     ("--permanent", "--add-rich-rule", MAC_RULE),
                     ("--permanent", "--remove-rich-rule", PORT_RULE),
                     ("--permanent", "--zone", "public", "--set-target=DROP"),
                     ("--reload",), ("--list-all",)):
            self.assertTrue(h.fw(*args)["ok"], args)
        self.assertEqual(h.consent_asked, [])


class NetworkCutOffTests(unittest.TestCase):
    """Blocks that would take the machine off its own network must be asked."""

    def _asks(self, rule):
        h = Harness(consent=False)
        resp = h.fw("--permanent", "--add-rich-rule", rule)
        return not resp["ok"] and h.ran == [] and h.consent_asked

    def test_ranges_ask(self):
        for net in ("10.0.0.0/8", "192.168.1.0/24", "192.168.1.66/31", "fd00::/64"):
            fam = "ipv6" if ":" in net else "ipv4"
            self.assertTrue(self._asks(
                f"rule family={fam} source address={net} drop"), net)

    def test_the_gateway_and_dns_ask(self):
        self.assertTrue(self._asks(f"rule family=ipv4 source address={GATEWAY} drop"))
        self.assertTrue(self._asks(f"rule family=ipv4 source address={DNS} drop"))
        self.assertTrue(self._asks(f"rule source mac={GATEWAY_MAC} drop"))
        self.assertTrue(self._asks(f"rule source mac={GATEWAY_MAC.upper()} drop"))

    def test_the_consent_uses_its_own_polkit_action(self):
        h = Harness(consent=True)
        self.assertTrue(h.fw("--permanent", "--add-rich-rule",
                             "rule family=ipv4 source address=10.0.0.0/8 drop")["ok"])
        self.assertEqual(h.consent_asked[0][1], H._POLKIT_ACTION_BLOCK)

    def test_the_internet_sized_ranges_are_refused_outright(self):
        h = Harness(consent=True)
        for net in ("0.0.0.0/0", "1.2.3.4/0", "0.0.0.0/1", "::/0", "2000::/3"):
            fam = "ipv6" if ":" in net else "ipv4"
            self.assertFalse(h.fw("--add-rich-rule",
                                  f"rule family={fam} source address={net} drop")["ok"])
        self.assertEqual(h.ran, [])


class ArgumentSmugglingTests(unittest.TestCase):
    def test_trailing_newline_and_control_characters_are_refused(self):
        for rule in (ADDR_RULE + "\n", ADDR_RULE + "\n accept", ADDR_RULE + "\x00",
                     "\n" + ADDR_RULE, ADDR_RULE.replace(" drop", " accept")):
            self.assertFalse(H._fwc_rule_ok(rule), repr(rule))

    def test_only_the_known_invocation_shapes_pass(self):
        h = Harness()
        refused = [
            ("--panic-on",), ("--direct", "--get-all-rules"),
            ("--set-default-zone", "trusted"), ("--set-default-zone=trusted",),
            ("--zone=trusted", "--add-rich-rule", ADDR_RULE),
            ("--zone", "evil", "--add-rich-rule", ADDR_RULE),
            ("--add-rich-rule",), ("--add-rich-rule", ADDR_RULE, "--reload"),
            ("--reload", "--reload"), ("--permanent",),
            ("--add-rich-rule", "--remove-rich-rule"),
            ("--set-target=ACCEPT",), ("--add-service=ssh",),
            ("--permanent", "--permanent", "--add-rich-rule", ADDR_RULE),
        ]
        for args in refused:
            self.assertFalse(h.fw(*args)["ok"], args)
        self.assertEqual(h.ran, [])

    def test_the_program_itself_cannot_be_chosen(self):
        h = Harness()
        for argv in (["/bin/sh", "-c", "id"], ["firewall-cmd ", "--reload"],
                     ["sh"], [], "firewall-cmd --reload", None, 7):
            resp = h.dispatch({"cmd": "fw_cmd", "args": argv})
            self.assertFalse(resp["ok"], argv)
        self.assertEqual(h.ran, [])


class SysctlTests(unittest.TestCase):
    def _set(self, key, value):
        h = Harness()
        resp = h.dispatch({"cmd": "sysctl_set", "key": key, "value": value})
        return resp["ok"], h.ran

    def test_values_that_would_cut_the_network_are_refused(self):
        for value in ("1", "0", "31", "256", "999", 1):
            ok, ran = self._set("net.ipv4.ip_default_ttl", value)
            self.assertFalse(ok, value)
            self.assertEqual(ran, [])

    def test_the_values_the_app_uses_pass(self):
        for key, value in (("net.ipv4.ip_default_ttl", "128"),
                           ("net.ipv4.ip_default_ttl", 64),
                           ("net.ipv6.conf.all.hop_limit", "64"),
                           ("net.ipv4.tcp_timestamps", "0"),
                           ("net.ipv4.tcp_timestamps", "1")):
            ok, ran = self._set(key, value)
            self.assertTrue(ok, (key, value))
            self.assertEqual(ran, [["sysctl", "-w", f"{key}={value}"]])

    def test_shapes_that_are_not_a_plain_number_are_refused(self):
        for value in ("64\n", " 64", "6 4", "0x40", "64; id", "-1", True, None,
                      [64], {"v": 64}, "１２８"):
            ok, ran = self._set("net.ipv4.ip_default_ttl", value)
            self.assertFalse(ok, repr(value))
            self.assertEqual(ran, [])

    def test_other_keys_are_refused(self):
        for key in ("kernel.core_pattern", "net.ipv4.ip_forward",
                    "net.ipv4.ip_default_ttl ", ["net.ipv4.ip_default_ttl"]):
            ok, ran = self._set(key, "64")
            self.assertFalse(ok, key)
            self.assertEqual(ran, [])


class ServiceControlTests(unittest.TestCase):
    def test_only_the_allowed_units_and_actions(self):
        h = Harness()
        for req in ({"cmd": "svc", "action": "stop", "unit": "sshd"},
                    {"cmd": "svc", "action": "mask", "unit": "avahi-daemon"},
                    {"cmd": "svc", "action": ["stop"], "unit": "avahi-daemon"},
                    {"cmd": "svc", "action": "stop", "unit": "avahi-daemon; id"},
                    {"cmd": "fw_service", "action": "mask"},
                    {"cmd": "fw_service", "action": {"x": 1}}):
            self.assertFalse(h.dispatch(req)["ok"], req)
        self.assertEqual(h.ran, [])

    def test_stopping_the_firewall_asks(self):
        h = Harness(consent=False)
        for action in ("stop", "disable"):
            self.assertFalse(h.dispatch({"cmd": "fw_service", "action": action})["ok"])
        self.assertEqual(h.ran, [])


class ProcessPrivacyTests(unittest.TestCase):
    """Root reads every command line; a caller gets only its own in full."""

    def _conns(self, peer_uid):
        from maze.protection import process_map
        entries = [{"remote_ip": "1.1.1.1", "remote_port": 443, "local": "x:1",
                    "inode": 1},
                   {"remote_ip": "1.1.1.1", "remote_port": 443, "local": "x:2",
                    "inode": 2}]
        inode_map = {1: (os.getpid(), "mine", "python3", "python3 --token=MINE"),
                     2: (1, "root-daemon", "daemon", "/usr/bin/daemon --password=SECRET")}
        with unittest.mock.patch.object(process_map, "_read_proc_net_tcp", lambda: entries), \
             unittest.mock.patch.object(process_map, "_build_inode_map", lambda: inode_map):
            resp = Harness(peer_uid=peer_uid).dispatch({"cmd": "proc_conns"})
        self.assertTrue(resp["ok"])
        return {c["process"]: c["cmdline"] for c in resp["data"]}

    def test_other_users_arguments_are_withheld(self):
        out = self._conns(os.getuid())
        self.assertEqual(out["mine"], "python3 --token=MINE")
        self.assertEqual(out["root-daemon"], "/usr/bin/daemon")
        self.assertNotIn("SECRET", json.dumps(out))

    def test_root_callers_see_everything(self):
        self.assertIn("SECRET", self._conns(0)["root-daemon"])


class ConnectionHardeningTests(unittest.TestCase):
    class _Transport:
        def __init__(self, queued):
            self.queued = queued

        def get_write_buffer_size(self):
            return self.queued

    class _Writer:
        def __init__(self, queued):
            self.transport = ConnectionHardeningTests._Transport(queued)
            self.written, self.closed = [], False

        def write(self, data):
            self.written.append(data)

        def close(self):
            self.closed = True

    def test_a_client_that_stops_reading_cannot_grow_root_memory(self):
        fast = self._Writer(0)
        lagging = self._Writer(H._PUSH_BUFFER_SOFT + 1)
        dead = self._Writer(H._PUSH_BUFFER_HARD + 1)
        with unittest.mock.patch.object(H, "_clients", [fast, lagging, dead]):
            H._deliver(b"{}\n")
            self.assertEqual(fast.written, [b"{}\n"])
            self.assertEqual(lagging.written, [])        # dropped, not queued
            self.assertTrue(dead.closed)
            self.assertNotIn(dead, H._clients)

    def test_the_number_of_clients_is_capped(self):
        writer = self._Writer(0)
        writer.get_extra_info = lambda _k: None
        crowd = [object()] * H._MAX_CLIENTS
        with unittest.mock.patch.object(H, "_clients", list(crowd)), \
             unittest.mock.patch.object(H, "_peer_allowed", lambda _w: True), \
             unittest.mock.patch.object(H, "_audit", lambda *_a: None):
            asyncio.run(H._handle(None, writer))
            self.assertTrue(writer.closed)
            self.assertEqual(len(H._clients), H._MAX_CLIENTS)

    def test_hostile_json_does_not_kill_the_connection(self):
        lines = [b"[" * 50000 + b"\n", b"\xff\xfe\n", b"[1,2,3]\n", b"\"str\"\n",
                 b"null\n", b'{"cmd": "ping", "id": 5}\n', b""]

        class Reader:
            async def readline(self_inner):
                line = lines.pop(0)
                if not line:
                    # Let the in-flight request answer before hanging up; a
                    # disconnect cancels whatever is still pending.
                    await asyncio.sleep(0.05)
                return line

        writer = self._Writer(0)
        writer.get_extra_info = lambda _k: None
        writer.drain = unittest.mock.AsyncMock()
        with unittest.mock.patch.object(H, "_clients", []), \
             unittest.mock.patch.object(H, "_peer_allowed", lambda _w: True):
            asyncio.run(H._handle(Reader(), writer))
        answers = [json.loads(w) for w in writer.written]
        self.assertEqual(answers, [{"id": 5, "ok": True}])


class ServiceIntegrationTests(unittest.TestCase):
    def test_version_reports_the_protocol(self):
        resp = Harness().dispatch({"cmd": "version", "id": 3})
        self.assertEqual(resp, {"id": 3, "ok": True, "data": {"protocol": H.PROTOCOL}})

    def test_sd_notify_reaches_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "notify")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(path)
            try:
                with unittest.mock.patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
                    self.assertTrue(H._sd_notify("READY=1"))
                self.assertEqual(sock.recv(64), b"READY=1")
            finally:
                sock.close()
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(H._sd_notify("READY=1"))

    def test_no_interface_means_wait_not_guess(self):
        with unittest.mock.patch("maze.utils.network_info.get_active_physical_interface",
                                 return_value="—"):
            self.assertEqual(H._resolve_iface(""), "")
            self.assertEqual(H._resolve_iface("does-not-exist0"), "")


# ── the fuzzer ─────────────────────────────────────────────────────────────────

_EVIL = ["", " ", "\n", "\x00", ";", "&&", "$(id)", "`id`", "|", "../../etc/shadow",
         "-c", "--", "--panic-on", "--direct", "--set-default-zone", "trusted",
         "--set-target=ACCEPT", "--zone=trusted", "--add-service=ssh",
         "--remove-service=ssh", "--add-masquerade", "--add-forward-port=port=22:proto=tcp:toaddr=1.2.3.4",
         "kernel.core_pattern", "|/tmp/x", "net.ipv4.ip_forward", "sshd", "root",
         "A" * 300, "é", "１２８", "1e3", "0x7f", "-1", "999999999999"]
_GOOD = ["firewall-cmd", "--permanent", "--zone", "public", "--add-rich-rule",
         "--remove-rich-rule", "--reload", "--list-all", "--set-target=DROP",
         "--set-target=default", PORT_RULE, ADDR_RULE, MAC_RULE,
         f"rule family=ipv4 source address={GATEWAY} drop",
         "rule family=ipv4 source address=10.0.0.0/8 drop",
         "rule family=ipv4 source address=0.0.0.0/0 drop",
         "net.ipv4.ip_default_ttl", "64", "128", "1", "avahi-daemon", "stop",
         "start", "is-active", "disable", "restart"]
_CMDS = ["ping", "version", "fw_list_all", "fw_cmd", "fw_list", "fw_state",
         "fw_service", "svc", "capture_stats", "sysctl_get", "sysctl_set",
         "nope", "", "__class__", None, 1, ["fw_cmd"]]


def _value(rng, depth=0):
    roll = rng.random()
    if roll < 0.45:
        return rng.choice(_GOOD)
    if roll < 0.75:
        return rng.choice(_EVIL) + (rng.choice(_GOOD) if rng.random() < 0.3 else "")
    if roll < 0.85 and depth < 2:
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return rng.choice([None, True, 0, -1, 2 ** 70, 3.5, {}, {"a": "b"}])


def _request(rng):
    req = {"cmd": rng.choice(_CMDS), "id": rng.choice([1, "x", None, [], 2 ** 80])}
    if rng.random() < 0.6:
        n = rng.randint(1, _FWC_MAX)
        req["args"] = (["firewall-cmd"] if rng.random() < 0.7 else []) + \
            [_value(rng) for _ in range(n)]
    for key in ("key", "value", "action", "unit"):
        if rng.random() < 0.5:
            req[key] = _value(rng)
    return req


_FWC_MAX = 7


class FuzzTests(unittest.TestCase):
    ITERATIONS = 4000

    def _invariants(self, h: Harness, req):
        for argv in h.ran:
            prog = argv[0]
            self.assertIn(prog, ("firewall-cmd", "systemctl", "sysctl"), (req, argv))
            if prog == "firewall-cmd":
                if len(argv) == 2 and argv[1] in ("--list-all", "--list-rich-rules",
                                                  "--query-panic"):
                    continue
                err, consent = H._fwc_check(argv)
                self.assertEqual(err, "", (req, argv))
                if consent:
                    self.assertTrue(h.consent_asked, f"ran without consent: {argv}")
            elif prog == "systemctl":
                action, unit = argv[1], argv[-1]
                if unit == H._FW_UNIT:
                    self.assertIn(action, H._FW_SVC_ACTIONS, argv)
                    if action in ("stop", "disable"):
                        self.assertTrue(h.consent_asked, argv)
                else:
                    self.assertIn(unit, H._SVC_ALLOWED, argv)
                    self.assertIn(action, H._SVC_ACTIONS, argv)
            else:
                if argv[1] == "-n":
                    self.assertIn(argv[2], H._SYSCTL_ALLOWED, argv)
                else:
                    key, value = argv[2].split("=", 1)
                    lo, hi = H._SYSCTL_ALLOWED[key]
                    self.assertTrue(value.isascii() and value.isdigit()
                                    and lo <= int(value) <= hi, argv)

    def test_hostile_requests_never_escape_the_allow_list(self):
        rng = random.Random(0xA11CE)
        executed = 0
        for _ in range(self.ITERATIONS):
            req = _request(rng)
            for consent in (False, True):
                h = Harness(consent=consent)
                try:
                    resp = h.dispatch(req)
                except Exception as exc:          # pragma: no cover
                    self.fail(f"dispatch raised {exc!r} for {req!r}")
                self.assertIsInstance(resp, dict)
                self.assertIn("ok", resp)
                json.dumps(resp)                  # always serialisable
                self._invariants(h, req)
                if not consent:
                    # Refused consent means nothing that needed it ran.
                    for argv in h.ran:
                        if argv[0] == "firewall-cmd" and len(argv) > 2:
                            self.assertEqual(H._fwc_check(argv)[1], "", argv)
                executed += len(h.ran)
        # The fuzzer must actually reach execution, or it proves nothing.
        self.assertGreater(executed, 200)


if __name__ == "__main__":
    unittest.main()
