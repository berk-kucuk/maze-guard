"""
Async client for the Maze privileged helper.
Runs in the normal-user GUI process.
"""
import asyncio
import json
import os
from typing import Callable

# Fixed socket published by the daemon (see maze/helper.py).
_SOCK_PATH = "/run/maze/maze.sock"


class HelperClient:
    def __init__(self, uid: int = None):
        self._uid = uid if uid is not None else os.getuid()
        self._sock = _SOCK_PATH
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._event_cbs: list[Callable] = []
        self._next_id = 1
        self._connected = False

    # ── connection ────────────────────────────────────────────────────────

    async def connect(self) -> bool:
        try:
            self._reader, self._writer = await asyncio.open_unix_connection(self._sock)
            self._connected = True
            asyncio.create_task(self._read_loop())
            return True
        except Exception:
            return False

    def is_connected(self) -> bool:
        return self._connected

    def on_event(self, cb: Callable) -> None:
        """Register callback for push events (arp, tcp, icmp, dhcp, error).

        Registration is idempotent: detectors re-register on every start, and
        they are restarted on every profile change, so appending blindly meant
        one captured packet was analysed N times after N switches.
        """
        if cb not in self._event_cbs:
            self._event_cbs.append(cb)

    def off_event(self, cb: Callable) -> None:
        """Deregister a push-event callback (called from a module's stop())."""
        if cb in self._event_cbs:
            self._event_cbs.remove(cb)

    async def close(self) -> None:
        self._connected = False
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass

    # ── internal I/O ─────────────────────────────────────────────────────

    async def _send(self, cmd: dict, timeout: float = 6.0) -> dict:
        req_id = self._next_id
        self._next_id += 1
        cmd["id"] = req_id

        # A dropped helper leaves callers holding a client that still looks
        # usable; answer them with a failed result instead of an AttributeError
        # surfacing in whichever UI slot happened to make the call.
        if not self._connected or self._writer is None:
            return {"id": req_id, "ok": False, "err": "helper not connected"}

        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut

        try:
            self._writer.write((json.dumps(cmd) + "\n").encode())
            await self._writer.drain()
        except Exception as exc:
            self._pending.pop(req_id, None)
            self._connected = False
            return {"id": req_id, "ok": False, "err": str(exc)}

        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            return {"id": req_id, "ok": False,
                    "err": f"the helper did not answer within {timeout:.0f}s"}

    async def _read_loop(self) -> None:
        try:
            async for raw in self._reader:
                line = raw.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "event" in msg:
                    for cb in self._event_cbs:
                        asyncio.create_task(cb(msg))
                elif "id" in msg:
                    rid = msg["id"]
                    fut = self._pending.pop(rid, None)
                    if fut and not fut.done():
                        fut.set_result(msg)
        except Exception:
            pass
        finally:
            self._connected = False

    # ── API ───────────────────────────────────────────────────────────────

    async def ping(self) -> bool:
        try:
            r = await self._send({"cmd": "ping"})
            return bool(r.get("ok"))
        except Exception:
            return False

    async def fw_list_all(self) -> str:
        r = await self._send({"cmd": "fw_list_all"})
        return r.get("data", "") if r.get("ok") else ""

    async def fw_cmd(self, args: list[str]) -> bool:
        """Run one firewall-cmd through the helper.

        The long timeout is there because a request that *reduces* protection
        (lowering the shield, removing a block) makes the helper raise a polkit
        prompt and wait for the user. Giving up at the default six seconds meant
        the UI declared failure while the dialog was still on screen — and then
        the operation went through anyway once the user typed their password,
        leaving the button contradicting the firewall.
        """
        r = await self._send({"cmd": "fw_cmd", "args": args}, timeout=120.0)
        return bool(r.get("ok"))

    async def fw_state(self) -> dict:
        """Snapshot of the firewall backend: installed/running/enabled, default
        zone, its target and panic mode. Empty dict when unavailable."""
        r = await self._send({"cmd": "fw_state"})
        return r.get("data", {}) if r.get("ok") else {}

    async def fw_service(self, action: str) -> tuple[bool, str]:
        """Drive the firewalld unit (start/stop/restart/is-active/...).
        Returns (ok, stdout-or-error).

        Given a long leash on purpose: firewalld rebuilds its entire ruleset on
        start, which routinely takes longer than the default request timeout.
        Giving up early made the UI report failure for a command that then
        succeeded a second later, leaving button and reality disagreeing.
        """
        query = action.startswith("is-")
        r = await self._send({"cmd": "fw_service", "action": action},
                             timeout=6.0 if query else 120.0)
        if r.get("ok"):
            return True, r.get("data", "")
        # An older daemon simply ignores commands it does not know, answering
        # ok=false with nothing else. Say so, instead of blaming systemctl for
        # a request it never received.
        return False, (r.get("err")
                       or "the privileged helper does not support firewall "
                          "service control — reinstall to update the daemon")

    async def fw_list(self) -> dict:
        r = await self._send({"cmd": "fw_list"})
        return r.get("data", {"ips": [], "ports_tcp": [], "ports_udp": []}) if r.get("ok") else {"ips": [], "ports_tcp": [], "ports_udp": []}

    async def svc(self, action: str, unit: str) -> tuple[bool, str]:
        """Run an allowlisted systemctl action. Returns (ok, stdout)."""
        r = await self._send({"cmd": "svc", "action": action, "unit": unit})
        return bool(r.get("ok")), r.get("data", "")

    async def proc_conns(self) -> list[dict] | None:
        """Full connection→process map built root-side, or None if unavailable."""
        r = await self._send({"cmd": "proc_conns"})
        return r.get("data") if r.get("ok") else None

    async def sysctl_get(self, key: str) -> str | None:
        r = await self._send({"cmd": "sysctl_get", "key": key})
        return r.get("data") if r.get("ok") else None

    async def sysctl_set(self, key: str, value: str) -> bool:
        r = await self._send({"cmd": "sysctl_set", "key": key, "value": value})
        return bool(r.get("ok"))

    async def maintain_connection(self) -> None:
        """Background reconnect loop: re-connects if the helper socket drops."""
        while True:
            await asyncio.sleep(10)
            if not self._connected:
                await self.connect()
