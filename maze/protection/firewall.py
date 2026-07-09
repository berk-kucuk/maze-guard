import asyncio
import re
import subprocess
from maze.utils.logger import log

# Safe, additive ruleset — policy accept so nothing is globally blocked.
# Rules are stored in named sets; individual IPs/ports can be added or
# removed without touching the rest of the firewall state.
_INIT_RULESET = """
table inet maze_firewall {
    set blocked_ips {
        type ipv4_addr
        flags interval
    }
    set blocked_ports_tcp {
        type inet_service
    }
    set blocked_ports_udp {
        type inet_service
    }
    chain input {
        type filter hook input priority filter - 10; policy accept;
        ip saddr @blocked_ips drop
        tcp dport @blocked_ports_tcp drop
        udp dport @blocked_ports_udp drop
    }
}
"""

_TABLE = "inet maze_firewall"

# Separate, self-contained table used only by the "block incoming" profile
# option. Kept apart from maze_firewall so enabling/disabling it never touches
# the user's explicit IP/port blocks. Allows established/related + loopback,
# drops unsolicited new inbound connections — safe for a client machine.
_SHIELD_RULESET = """
table inet maze_shield {
    chain input {
        type filter hook input priority filter - 5; policy accept;
        ct state established,related accept
        iif lo accept
        ct state new drop
    }
}
"""


class FirewallManager:
    def __init__(self):
        self._helper = None
        self._initialized = False

    async def start(self, bus, helper=None) -> None:
        self._helper = helper

    async def stop(self) -> None:
        pass  # Leave rules in place — user explicitly manages them

    # ── init ──────────────────────────────────────────────────────────────

    async def ensure_init(self) -> bool:
        """Create the maze_firewall table if it doesn't exist yet."""
        if self._initialized:
            return True
        ok = await self._nft_apply(_INIT_RULESET)
        if ok:
            self._initialized = True
        return ok

    async def flush(self) -> None:
        """Remove the entire Maze firewall table (clears all rules)."""
        await self._nft_run(["nft", "delete", "table", "inet", "maze_firewall"])
        self._initialized = False

    # ── public API ────────────────────────────────────────────────────────

    async def block_ip(self, ip: str) -> bool:
        if not await self.ensure_init():
            return False
        return await self._nft_run(
            ["nft", "add", "element", "inet", "maze_firewall",
             "blocked_ips", "{", ip, "}"]
        )

    async def unblock_ip(self, ip: str) -> bool:
        return await self._nft_run(
            ["nft", "delete", "element", "inet", "maze_firewall",
             "blocked_ips", "{", ip, "}"]
        )

    async def block_port(self, port: int, proto: str = "tcp") -> bool:
        if not await self.ensure_init():
            return False
        set_name = f"blocked_ports_{proto}"
        return await self._nft_run(
            ["nft", "add", "element", "inet", "maze_firewall",
             set_name, "{", str(port), "}"]
        )

    async def unblock_port(self, port: int, proto: str = "tcp") -> bool:
        set_name = f"blocked_ports_{proto}"
        return await self._nft_run(
            ["nft", "delete", "element", "inet", "maze_firewall",
             set_name, "{", str(port), "}"]
        )

    # ── incoming shield (profile-driven) ──────────────────────────────────

    async def enable_incoming_block(self) -> bool:
        """Drop unsolicited inbound connections (established/related still flow)."""
        return await self._nft_apply(_SHIELD_RULESET)

    async def disable_incoming_block(self) -> bool:
        """Remove the incoming shield, restoring the default accept behaviour."""
        return await self._nft_run(
            ["nft", "delete", "table", "inet", "maze_shield"]
        )

    async def list_rules(self) -> dict:
        """Return {'ips': [...], 'ports_tcp': [...], 'ports_udp': [...]}"""
        if self._helper and self._helper.is_connected():
            return await self._helper.fw_list()
        return await asyncio.to_thread(self._parse_rules)

    # ── internals ─────────────────────────────────────────────────────────

    async def _nft_apply(self, ruleset: str) -> bool:
        if self._helper and self._helper.is_connected():
            return await self._helper.nft_apply(ruleset)
        r = await asyncio.to_thread(
            subprocess.run,
            ["nft", "-f", "-"],
            input=ruleset, text=True, capture_output=True,
        )
        return r.returncode == 0

    async def _nft_run(self, cmd: list[str]) -> bool:
        if self._helper and self._helper.is_connected():
            return await self._helper.fw_cmd(cmd)
        r = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log.warning(f"nft error: {r.stderr.strip()}")
        return r.returncode == 0

    def _parse_rules(self) -> dict:
        result = {"ips": [], "ports_tcp": [], "ports_udp": []}
        try:
            out = subprocess.run(
                ["nft", "list", "table", "inet", "maze_firewall"],
                capture_output=True, text=True,
            ).stdout
            for line in out.splitlines():
                m = re.search(r"elements\s*=\s*\{([^}]+)\}", line)
                if not m:
                    continue
                elements = [e.strip() for e in m.group(1).split(",") if e.strip()]
                if "blocked_ips" in line:
                    result["ips"] = elements
                elif "blocked_ports_tcp" in line:
                    result["ports_tcp"] = [int(p) for p in elements if p.isdigit()]
                elif "blocked_ports_udp" in line:
                    result["ports_udp"] = [int(p) for p in elements if p.isdigit()]
        except Exception:
            pass
        return result
