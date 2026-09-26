"""
Close the service-discovery and file-sharing ports a desktop leaves open.

On a home network these protocols are what makes printers, media players and
shared folders appear by themselves. On a public network they are an
advertisement: mDNS and LLMNR answer with the machine's hostname, NetBIOS with
its workgroup and user, SSDP and WS-Discovery with its device description, and
445 with whatever Samba is willing to talk about. Each one tells a stranger on
the same access point who you are before they have probed anything.

Two things this module used to get wrong, both of which made it report success
while doing nothing:

* Without the privileged helper every rule silently failed, and it *still* set
  itself active — so the interface showed a green "Active" for a protection
  that had not been applied. It now refuses to start rather than lie.
* Rules were written without naming a zone, which lands them in whatever
  firewalld considers default at that moment; the rest of the application
  operates on the zone it read from the firewall. On a host whose default zone
  is not the active one, the rules went somewhere they had no effect.
"""
import asyncio

from maze.core.verify import FAIL, PASS, Verdict, WARN
from maze.utils.logger import log

# (protocol, port, what it leaks). Inbound drops only — nothing here stops the
# machine from *finding* other devices, only from answering strangers.
_BLOCKED = [
    ("udp", 5353, "mDNS/Bonjour — hostname and service list"),
    ("udp", 5355, "LLMNR — hostname resolution"),
    ("udp", 137,  "NetBIOS name service — hostname and workgroup"),
    ("udp", 138,  "NetBIOS datagram service"),
    ("tcp", 139,  "NetBIOS session service"),
    ("tcp", 445,  "SMB — file shares"),
    ("udp", 1900, "SSDP/UPnP — device description"),
    ("udp", 3702, "WS-Discovery — printers and scanners"),
]
_FAMILIES = ("ipv4", "ipv6")


class ServiceBlocker:
    """Block service-discovery ports through firewalld rich rules.

    Every rule is added through the privileged helper daemon (running as root
    under systemd) so the interface never raises a password prompt. There is
    deliberately no direct-subprocess fallback: that path would trigger a
    polkit dialog from a background module the user did not click on.
    """

    def __init__(self):
        self._helper = None
        self._zone = ""
        self._applied: list[tuple[str, str, int]] = []   # (family, proto, port)

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, bus, helper=None) -> None:
        self._helper = helper
        if not (helper and helper.is_connected()):
            raise PermissionError(
                "the privileged helper is not connected, so firewall rules "
                "cannot be installed")
        self._zone = await self._default_zone()
        if not self._zone:
            raise RuntimeError(
                "firewalld is not running, so service ports cannot be blocked")

        self._applied = []
        failed: list[str] = []
        for proto, port, _why in _BLOCKED:
            for family in _FAMILIES:
                if await self._rule("--add-rich-rule", family, proto, port):
                    self._applied.append((family, proto, port))
                else:
                    failed.append(f"{proto}/{port} ({family})")
        await self._reload()

        if not self._applied:
            raise RuntimeError(
                "firewalld accepted none of the service-block rules "
                + (f"({failed[0]} failed)" if failed else ""))
        if failed:
            # Partial success is still protection, but the user is entitled to
            # know which doors stayed open rather than seeing a plain "Active".
            log.warning("ServiceBlocker: could not block " + ", ".join(failed))

    async def stop(self) -> None:
        if not (self._helper and self._helper.is_connected()):
            self._applied = []
            return
        for family, proto, port in list(self._applied):
            await self._rule("--remove-rich-rule", family, proto, port)
        if self._applied:
            await self._reload()
        self._applied = []

    # ── what the interface shows ─────────────────────────────────────────

    def status_detail(self) -> str:
        if not self._applied:
            return ""
        ports = sorted({f"{proto}/{port}" for _f, proto, port in self._applied})
        return f"{len(ports)} inbound ports dropped: " + ", ".join(ports)

    # ── self-test ────────────────────────────────────────────────────────

    async def verify(self) -> Verdict:
        """Ask firewalld what it is enforcing, not what we asked it to enforce.

        The two came apart before: rules were sent to a zone that was not the
        active one, and nothing checked whether they arrived. This reads the
        live rule list back.
        """
        if not (self._helper and self._helper.is_connected()):
            return Verdict(FAIL,
                           "the privileged helper is not connected, so the "
                           "firewall cannot be asked what it is enforcing")
        rules = await self._helper.fw_list()
        live = ({("tcp", p) for p in rules.get("ports_tcp", [])}
                | {("udp", p) for p in rules.get("ports_udp", [])})
        missing = [(proto, port, why) for proto, port, why in _BLOCKED
                   if (proto, port) not in live]
        blocked = [f"{proto}/{port}" for proto, port, _ in _BLOCKED
                   if (proto, port) in live]
        if not missing:
            return Verdict(PASS,
                           f"firewalld is dropping all {len(_BLOCKED)} "
                           f"discovery ports inbound",
                           [f"blocked: {', '.join(blocked)}"])
        if not blocked:
            return Verdict(FAIL,
                           "firewalld holds none of the discovery-port block "
                           "rules — this machine answers mDNS, NetBIOS and "
                           "SSDP probes from anyone on the network",
                           [f"open: {proto}/{port} — {why}"
                            for proto, port, why in missing])
        return Verdict(WARN,
                       f"{len(blocked)} of {len(_BLOCKED)} discovery ports are "
                       f"blocked; the rest are still answering",
                       [f"blocked: {', '.join(blocked)}"]
                       + [f"open: {proto}/{port} — {why}"
                          for proto, port, why in missing])

    # ── firewall plumbing ────────────────────────────────────────────────

    async def _default_zone(self) -> str:
        """The zone the firewall is actually using, or "" if it is not running."""
        state = await self._helper.fw_state()
        if state:
            return state.get("zone", "") if state.get("running") else ""
        # An older daemon has no fw_state; --list-all still names the zone on
        # its first line ("public (default, active)").
        raw = await self._helper.fw_list_all()
        return raw.split()[0] if raw.strip() else ""

    async def _rule(self, action: str, family: str, proto: str,
                    port: int) -> bool:
        rule = f"rule family={family} port port={port} protocol={proto} drop"
        return await self._fw(["--permanent", "--zone", self._zone,
                               action, rule])

    async def _reload(self) -> None:
        await self._fw(["--reload"])

    async def _fw(self, args: list[str]) -> bool:
        if not (self._helper and self._helper.is_connected()):
            return False
        return await self._helper.fw_cmd(["firewall-cmd"] + args)
