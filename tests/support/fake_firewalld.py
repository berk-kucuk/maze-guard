"""
The real privileged helper, run in-process against a simulated firewalld.

Everything the interface asks of the firewall goes through
``maze.helper._dispatch`` — the same allow-list, rule validation and consent
checks the root daemon applies — and only the final ``systemctl`` /
``firewall-cmd`` process is replaced by ``FakeFirewalld``. A rule the GUI
spells in a way the helper would refuse therefore fails here too.

Packets can be pushed into the detectors with ``InProcessHelper.push``, exactly
as the daemon's capture thread would.
"""
import asyncio
import re
import unittest.mock

import maze.helper as helper_mod
from maze.helper_client import HelperClient

_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _normalise(rule: str) -> str:
    """firewalld stores rules with quoted values; compare without quotes."""
    return " ".join(rule.replace('"', "").split())


def _quoted(rule: str) -> str:
    """How `firewall-cmd --list-rich-rules` prints a stored rule."""
    return _KV.sub(lambda m: f'{m.group(1)}="{m.group(2).strip(chr(34))}"', rule)


class FakeFirewalld:
    def __init__(self, running: bool = True, zone: str = "public"):
        self.running = running
        self.enabled = True
        self.zone = zone
        self.target = "default"
        self.rules: list[str] = []
        self.commands: list[list[str]] = []
        # Other things the helper may touch: systemd units and sysctls.
        self.units = {"avahi-daemon": True, "avahi-daemon.socket": True}
        self.sysctl = {"net.ipv4.ip_default_ttl": "64",
                       "net.ipv6.conf.all.hop_limit": "64",
                       "net.ipv4.tcp_timestamps": "1",
                       "net.ipv4.tcp_window_scaling": "1"}

    # what `_run` returns
    @staticmethod
    def _done(code: int = 0, out: str = "", err: str = ""):
        return helper_mod._Completed(returncode=code, stdout=out, stderr=err)

    async def run(self, args: list[str], timeout: float = 10.0):
        self.commands.append(list(args))
        if args[0] == "sysctl":
            if args[1] == "-n":
                return self._done(0, self.sysctl.get(args[2], ""))
            key, value = args[2].split("=", 1)
            self.sysctl[key] = value
            return self._done(0, f"{key} = {value}")
        if args[0] == "systemctl" and args[-1] != "firewalld":
            action, unit = args[1], args[-1]
            if action == "is-active":
                up = self.units.get(unit, False)
                return self._done(0 if up else 3, "active" if up else "inactive")
            self.units[unit] = action in ("start", "restart")
            return self._done()
        if args[0] == "systemctl":
            action = args[1]
            if action == "is-active":
                return self._done(0 if self.running else 3,
                                  "active" if self.running else "inactive")
            if action == "is-enabled":
                return self._done(0, "enabled" if self.enabled else "disabled")
            if action in ("start", "restart"):
                self.running = True
            elif action == "stop":
                self.running = False
            elif action == "enable":
                self.enabled = True
            elif action == "disable":
                self.enabled = False
            return self._done()
        if args[0] != "firewall-cmd":
            return self._done(1, err="unexpected command")
        if not self.running:
            return self._done(252, err="FirewallD is not running")
        flags = args[1:]
        if "--list-all" in flags:
            body = [f"{self.zone} (default, active)", f"  target: {self.target}",
                    "  services: dhcpv6-client ssh", "  rich rules:"]
            body += [f"\t{_quoted(r)}" for r in self.rules]
            return self._done(0, "\n".join(body) + "\n")
        if "--list-rich-rules" in flags:
            return self._done(0, "".join(_quoted(r) + "\n" for r in self.rules))
        if "--query-panic" in flags:
            return self._done(1, "no")
        if "--get-default-zone" in flags:
            return self._done(0, self.zone)
        if "--reload" in flags:
            return self._done(0, "success")
        for flag in flags:
            if flag.startswith("--set-target="):
                self.target = flag.split("=", 1)[1]
                return self._done(0, "success")
        if "--add-rich-rule" in flags:
            rule = _normalise(flags[flags.index("--add-rich-rule") + 1])
            if rule not in self.rules:
                self.rules.append(rule)
            return self._done(0, "success")
        if "--remove-rich-rule" in flags:
            rule = _normalise(flags[flags.index("--remove-rich-rule") + 1])
            if rule in self.rules:
                self.rules.remove(rule)
            # firewalld warns NOT_ENABLED and still exits 0
            return self._done(0, "success")
        return self._done(2, err=f"unsupported: {flags}")

    # convenience for assertions
    def has(self, needle: str) -> bool:
        return any(needle in r for r in self.rules)


class InProcessHelper(HelperClient):
    """A HelperClient whose requests are served by the real helper code."""

    def __init__(self, firewalld: FakeFirewalld, consent: bool = True):
        super().__init__(uid=1000)
        self.fw = firewalld
        self.consent = consent
        self.consent_asked: list[str] = []
        self._connected = True
        self.requests: list[dict] = []

    async def connect(self) -> bool:
        self._connected = True
        return True

    async def _send(self, cmd: dict, timeout: float = 6.0) -> dict:
        self.requests.append(dict(cmd))
        if not self._connected:
            return {"id": 0, "ok": False, "err": "helper not connected"}

        async def authorized(_writer, what, action=helper_mod._POLKIT_ACTION):
            self.consent_asked.append(what)
            return (True, "") if self.consent else (False, "authorisation was declined")

        helper_mod._fw_forget()
        with unittest.mock.patch.object(helper_mod, "_run", self.fw.run), \
             unittest.mock.patch.object(helper_mod, "_authorized", authorized), \
             unittest.mock.patch.object(helper_mod, "_fw_unit_installed", lambda: True), \
             unittest.mock.patch.object(helper_mod, "_audit", lambda *_a: None), \
             unittest.mock.patch.object(helper_mod, "_default_gateways",
                                        lambda: {"192.168.1.1"}), \
             unittest.mock.patch.object(helper_mod, "_nameservers",
                                        lambda: {"192.168.1.1"}), \
             unittest.mock.patch.object(helper_mod, "_gateway_macs",
                                        lambda _g: {"ac:15:a2:52:45:0b"}):
            return await helper_mod._dispatch(cmd, None)

    async def push(self, event: dict) -> None:
        """Deliver one capture event to every subscribed detector."""
        for cb in list(self._event_cbs):
            await cb(event)
        await asyncio.sleep(0)
