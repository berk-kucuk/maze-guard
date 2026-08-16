import re
from dataclasses import dataclass, field

from maze.utils.logger import log

# Rich-rule logging clause attached to every block Maze Guard installs. The
# kernel log line it produces is the only record that survives a restart, so an
# auto-block can still be justified after the fact. The rate cap keeps a
# hammering attacker from filling the journal.
_LOG_CLAUSE = "log prefix=MAZE-BLOCK level=info limit value=3/m "

_IPV6_HINT = re.compile(r'^[0-9a-fA-F:]+(?:/\d{1,3})?$')


@dataclass
class FirewallState:
    """What the firewall backend is actually doing right now."""
    installed: bool = False
    running: bool = False
    enabled: bool = False          # starts at boot
    enabled_known: bool = True     # False when derived without asking systemd
    zone: str = ""
    target: str = ""               # "DROP" while the inbound shield is up
    panic: bool = False
    rules: dict = field(default_factory=dict)

    @property
    def incoming_blocked(self) -> bool:
        return self.running and self.target.upper() == "DROP"

    @property
    def available(self) -> bool:
        return self.installed


class FirewallManager:
    """Manage the firewalld backend: on/off, the inbound shield, and rules.

    ALL firewall-cmd calls (read AND write) are routed through the privileged
    helper daemon. When the helper is unavailable, operations are reported as
    failures — NEVER fall back to direct subprocess calls that would trigger a
    polkit password prompt.
    """

    def __init__(self):
        self._helper = None
        self._initialized = False
        self._zone: str = ""
        self._state = FirewallState()
        self._last_error: str = ""

    async def start(self, bus, helper=None) -> None:
        self._helper = helper
        await self.sync_state()

    async def stop(self) -> None:
        pass

    # ── internal ──────────────────────────────────────────────────────────

    def _has_helper(self) -> bool:
        return self._helper is not None and self._helper.is_connected()

    async def _fw_cmd(self, args: list[str]) -> bool:
        """Run firewall-cmd through the root helper. No fallback."""
        if not self._has_helper():
            self._last_error = "privileged helper not connected"
            return False
        ok = await self._helper.fw_cmd(["firewall-cmd"] + args)
        if not ok:
            self._last_error = f"firewall-cmd {' '.join(args)} failed"
        return ok

    @staticmethod
    def _family(ip: str) -> str:
        return "ipv6" if ":" in ip and _IPV6_HINT.match(ip) else "ipv4"

    def _ip_rule(self, ip: str, with_log: bool = True) -> str:
        return (f'rule family={self._family(ip)} source address={ip} '
                f'{_LOG_CLAUSE if with_log else ""}drop')

    @staticmethod
    def _port_rule(port: int, proto: str, with_log: bool = True) -> str:
        return (f'rule family=ipv4 port port={port} protocol={proto} '
                f'{_LOG_CLAUSE if with_log else ""}drop')

    @property
    def last_error(self) -> str:
        return self._last_error

    # ── init / state ──────────────────────────────────────────────────────

    async def ensure_init(self) -> bool:
        if self._initialized:
            return True
        if not self._has_helper():
            self._last_error = "privileged helper not connected"
            return False
        if not self._zone:
            self._zone = await self._get_zone()
        if self._zone:
            self._initialized = True
            return True
        self._last_error = "could not determine the active firewall zone"
        return False

    async def _get_zone(self) -> str:
        """Get default zone via the helper's fw_list_all which runs as root."""
        if not self._has_helper():
            return ""
        raw = await self._helper.fw_list_all()
        # First line of --list-all: "public (default, active)"
        if raw:
            return raw.split()[0]
        return ""

    @property
    def state(self) -> FirewallState:
        """Last known state. Refreshed by sync_state(); never blocks."""
        return self._state

    async def sync_state(self) -> FirewallState:
        """Re-read the live firewall state.

        Everything the UI shows is derived from this rather than from flags we
        set when a command succeeded: the zone target is written with
        --permanent, so it outlives the process, and firewalld can equally be
        changed by firewall-cmd, a distro tool, or another admin session. An
        in-memory flag is a guess; this is the answer.
        """
        if not self._has_helper():
            self._state = FirewallState()
            return self._state
        raw = await self._helper.fw_state()
        if not raw:
            # A helper daemon older than this GUI does not know fw_state. Rather
            # than report the firewall as missing — which would be a lie, and
            # would grey out controls that do work — reconstruct what we can
            # from --list-all, which every version has always supported.
            self._state = await self._state_from_list_all()
            return self._state
        state = FirewallState(
            installed=bool(raw.get("installed")),
            running=bool(raw.get("running")),
            enabled=bool(raw.get("enabled")),
            zone=raw.get("zone", ""),
            target=raw.get("target", ""),
            panic=bool(raw.get("panic")),
        )
        if state.zone:
            self._zone = state.zone
            self._initialized = True
        if state.running:
            state.rules = await self._helper.fw_list()
        self._state = state
        return state

    async def _state_from_list_all(self) -> FirewallState:
        """Derive state from `firewall-cmd --list-all` alone.

        Output starts with "public (default, active)" followed by indented
        keys, one of which is the zone target. Empty output means firewalld is
        not answering, which for our purposes means it is not running.
        """
        raw = await self._helper.fw_list_all()
        if not raw.strip():
            return FirewallState(installed=True, running=False,
                                 enabled_known=False)
        state = FirewallState(installed=True, running=True,
                              enabled_known=False, zone=raw.split()[0])
        for line in raw.splitlines():
            s = line.strip().lower()
            if s.startswith("target:"):
                state.target = s.split(":", 1)[1].strip()
                break
        if state.zone:
            self._zone = state.zone
            self._initialized = True
        state.rules = await self._helper.fw_list()
        return state

    # ── backend on/off ────────────────────────────────────────────────────

    async def is_running(self) -> bool:
        return (await self.sync_state()).running

    async def enable_firewall(self) -> bool:
        """Start the firewall backend (and restore the inbound shield state)."""
        self._last_error = ""
        if not self._has_helper():
            self._last_error = "privileged helper not connected"
            return False
        ok, out = await self._helper.fw_service("start")
        if not ok:
            self._last_error = out or "systemctl start firewalld failed"
            log.warning(f"firewall start failed: {self._last_error}")
        else:
            self._initialized = False      # zone must be re-read after start
            await self.sync_state()
        return ok

    async def disable_firewall(self) -> bool:
        """Stop the firewall backend entirely. The machine is unprotected after
        this; callers are expected to have confirmed with the user first."""
        self._last_error = ""
        if not self._has_helper():
            self._last_error = "privileged helper not connected"
            return False
        ok, out = await self._helper.fw_service("stop")
        if not ok:
            self._last_error = out or "systemctl stop firewalld failed"
            log.warning(f"firewall stop failed: {self._last_error}")
        else:
            log.warning("firewalld stopped on user request — host is unprotected")
            await self.sync_state()
        return ok

    async def toggle_firewall(self) -> bool:
        if (await self.sync_state()).running:
            return await self.disable_firewall()
        return await self.enable_firewall()

    # ── rules ─────────────────────────────────────────────────────────────

    async def flush(self) -> None:
        if not await self.ensure_init():
            return
        rules = await self._helper.fw_list()
        for ip in rules.get("ips", []):
            for rule in (self._ip_rule(ip), self._ip_rule(ip, with_log=False)):
                await self._fw_cmd(["--permanent", "--zone", self._zone,
                                    "--remove-rich-rule", rule])
        for proto_key, proto in [("ports_tcp", "tcp"), ("ports_udp", "udp")]:
            for port in rules.get(proto_key, []):
                for rule in (self._port_rule(port, proto),
                             self._port_rule(port, proto, with_log=False)):
                    await self._fw_cmd(["--permanent", "--zone", self._zone,
                                        "--remove-rich-rule", rule])
        await self._fw_cmd(["--reload"])

    async def block_ip(self, ip: str) -> bool:
        if not await self.ensure_init():
            return False
        ok = await self._fw_cmd(["--permanent", "--zone", self._zone,
                                 "--add-rich-rule", self._ip_rule(ip)])
        if ok:
            await self._fw_cmd(["--reload"])
        return ok

    async def unblock_ip(self, ip: str) -> bool:
        if not await self.ensure_init():
            return False
        # Rules written before logging was added carry no log clause; try both
        # spellings so an old rule is still removable.
        ok = await self._fw_cmd(["--permanent", "--zone", self._zone,
                                 "--remove-rich-rule", self._ip_rule(ip)])
        ok |= await self._fw_cmd(["--permanent", "--zone", self._zone,
                                  "--remove-rich-rule",
                                  self._ip_rule(ip, with_log=False)])
        if ok:
            await self._fw_cmd(["--reload"])
        return ok

    async def block_port(self, port: int, proto: str = "tcp") -> bool:
        if not await self.ensure_init():
            return False
        ok = await self._fw_cmd(["--permanent", "--zone", self._zone,
                                 "--add-rich-rule", self._port_rule(port, proto)])
        if ok:
            await self._fw_cmd(["--reload"])
        return ok

    async def unblock_port(self, port: int, proto: str = "tcp") -> bool:
        if not await self.ensure_init():
            return False
        ok = await self._fw_cmd(["--permanent", "--zone", self._zone,
                                 "--remove-rich-rule",
                                 self._port_rule(port, proto)])
        ok |= await self._fw_cmd(["--permanent", "--zone", self._zone,
                                  "--remove-rich-rule",
                                  self._port_rule(port, proto, with_log=False)])
        if ok:
            await self._fw_cmd(["--reload"])
        return ok

    # ── inbound shield ────────────────────────────────────────────────────

    async def enable_incoming_block(self) -> bool:
        self._last_error = ""
        if not await self.ensure_init():
            return False
        # Set the zone's default target to DROP instead of switching zones.
        # This blocks unsolicited inbound traffic while preserving explicitly
        # allowed services in the zone (e.g. kdeconnect, ssh) that would be
        # silently ignored if we switched to the "drop" zone.
        ok = await self._fw_cmd(["--permanent", "--zone", self._zone,
                                 "--set-target=DROP"])
        if ok:
            await self._fw_cmd(["--reload"])
            await self.sync_state()
        return ok

    async def disable_incoming_block(self) -> bool:
        self._last_error = ""
        # ensure_init matters here: without it a click before the first state
        # sync fell back to the literal zone "public" and silently retargeted
        # the wrong zone on any host whose default is something else.
        if not await self.ensure_init():
            return False
        ok = await self._fw_cmd(["--permanent", "--zone", self._zone,
                                 "--set-target=default"])
        if ok:
            await self._fw_cmd(["--reload"])
            await self.sync_state()
        return ok

    def is_incoming_blocked(self) -> bool:
        """Cached answer for synchronous UI paints. sync_state() refreshes it."""
        return self._state.incoming_blocked

    # ── list rules ────────────────────────────────────────────────────────

    async def list_rules(self) -> dict:
        if self._has_helper():
            return await self._helper.fw_list()
        return {"ips": [], "ports_tcp": [], "ports_udp": []}
