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
        """Register callback for push events (arp, syn, error)."""
        self._event_cbs.append(cb)

    async def close(self) -> None:
        self._connected = False
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass

    # ── internal I/O ─────────────────────────────────────────────────────

    async def _send(self, cmd: dict) -> dict:
        req_id = self._next_id
        self._next_id += 1
        cmd["id"] = req_id

        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut

        self._writer.write((json.dumps(cmd) + "\n").encode())
        await self._writer.drain()

        try:
            return await asyncio.wait_for(fut, timeout=6.0)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            return {"id": req_id, "ok": False, "err": "timeout"}

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

    async def nft_list(self) -> str:
        r = await self._send({"cmd": "nft_list"})
        return r.get("data", "") if r.get("ok") else ""

    async def nft_apply(self, rules: str) -> bool:
        r = await self._send({"cmd": "nft_apply", "rules": rules})
        return bool(r.get("ok"))

    async def nft_delete(self, table: str) -> bool:
        r = await self._send({"cmd": "nft_delete", "table": table})
        return bool(r.get("ok"))

    async def set_mac(self, iface: str, mac: str) -> bool:
        r = await self._send({"cmd": "set_mac", "iface": iface, "mac": mac})
        return bool(r.get("ok"))

    async def fw_cmd(self, args: list[str]) -> bool:
        r = await self._send({"cmd": "fw_cmd", "args": args})
        return bool(r.get("ok"))

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
