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
# Longest response line accepted. asyncio's default is 64 KB, and a proc_conns
# answer on a busy desktop (every connection, with its command line) passes
# that: the read loop died on the overrun and the helper dropped to
# "disconnected" every time the connection map refreshed.
_LINE_LIMIT = 16 * 1024 * 1024
# The request vocabulary this GUI expects (maze/helper.py PROTOCOL). A daemon
# that answers with less — or does not know "version" at all — predates fixes
# this GUI relies on, and the user is told to restart or reinstall it.
EXPECTED_PROTOCOL = 2


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
        self.protocol: int | None = None     # None until asked

    # ── connection ────────────────────────────────────────────────────────

    async def connect(self) -> bool:
        try:
            self._reader, self._writer = await asyncio.open_unix_connection(
                self._sock, limit=_LINE_LIMIT)
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
            # Nothing will answer these now; fail them instead of leaving each
            # caller to sit out its own timeout (two minutes for fw_cmd).
            pending, self._pending = self._pending, {}
            for rid, fut in pending.items():
                if not fut.done():
                    fut.set_result({"id": rid, "ok": False,
                                    "err": "helper connection lost"})

    # ── API ───────────────────────────────────────────────────────────────

    async def version(self) -> int:
        """The daemon's protocol number; 0 for a daemon too old to say."""
        r = await self._send({"cmd": "version"})
        data = r.get("data") if r.get("ok") else None
        proto = data.get("protocol") if isinstance(data, dict) else 0
        self.protocol = proto if isinstance(proto, int) else 0
        return self.protocol

    @property
    def outdated(self) -> bool:
        return self.protocol is not None and self.protocol < EXPECTED_PROTOCOL

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

    async def fw_state(self) -> dict | None:
        """Snapshot of the firewall backend: installed/running/enabled, default
        zone, its target and panic mode.

        Three answers, because callers must treat them differently:
          dict  — the state;
          {}    — a daemon older than fw_state (it ignores the command or says
                  "unknown command"): fall back to what old daemons support;
          None  — the daemon has fw_state but could not answer just now (a
                  timeout, a probe that failed, the connection dropping). That
                  is NOT an old daemon, and reporting it as one sent people to
                  restart a helper that was up to date.
        """
        r = await self._send({"cmd": "fw_state"})
        if r.get("ok"):
            return r.get("data", {})
        err = str(r.get("err") or "")
        if not err or err.startswith("unknown command"):
            return {}
        return None

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
        empty = {"ips": [], "ports_tcp": [], "ports_udp": [], "macs": []}
        r = await self._send({"cmd": "fw_list"})
        if not r.get("ok"):
            return empty
        return {**empty, **(r.get("data") or {})}

    async def svc(self, action: str, unit: str) -> tuple[bool, str]:
        """Run an allowlisted systemctl action. Returns (ok, stdout)."""
        r = await self._send({"cmd": "svc", "action": action, "unit": unit})
        return bool(r.get("ok")), r.get("data", "")

    async def proc_conns(self) -> list[dict] | None:
        """Full connection→process map built root-side, or None if unavailable."""
        r = await self._send({"cmd": "proc_conns"})
        return r.get("data") if r.get("ok") else None

    async def capture_stats(self) -> dict:
        """How much traffic the daemon's capture has seen since it started.

        Empty dict when the running daemon is too old to answer — callers must
        treat that as "cannot tell", never as zero, since zero is the one
        reading that would be actively misleading.
        """
        r = await self._send({"cmd": "capture_stats"})
        return r.get("data", {}) if r.get("ok") else {}

    async def sysctl_get(self, key: str) -> str | None:
        r = await self._send({"cmd": "sysctl_get", "key": key})
        return r.get("data") if r.get("ok") else None

    async def sysctl_set(self, key: str, value: str) -> bool:
        r = await self._send({"cmd": "sysctl_set", "key": key, "value": value})
        return bool(r.get("ok"))
