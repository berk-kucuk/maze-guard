import asyncio
import os
import socket
import struct
from dataclasses import dataclass
from maze.core.events import Event, EventBus, EventType, ThreatLevel

_SEEN_MAX = 2000   # prune seen-set when it exceeds this size


@dataclass
class Connection:
    pid: int
    process: str
    local_addr: str
    remote_addr: str
    remote_ip: str
    remote_port: int


def _hex_to_ip(hex_str: str) -> str:
    addr = int(hex_str, 16)
    return socket.inet_ntoa(struct.pack("<I", addr))


def _hex_to_ip6(hex_str: str) -> str:
    """Convert 32-char /proc/net/tcp6 hex to standard IPv6 notation.

    Each 32-bit word is stored little-endian; we unpack LE then repack BE
    to get the correct network-byte-order IPv6 address.
    """
    raw = bytes.fromhex(hex_str)
    words = struct.unpack("<4I", raw)
    big = struct.pack(">4I", *words)
    return socket.inet_ntop(socket.AF_INET6, big)


def _unwrap_mapped(ip: str) -> str:
    """Convert IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4.

    This ensures whitelist and port-based checks work regardless of whether
    the kernel used an IPv4 or IPv6 socket for the same connection.
    """
    if ip.startswith("::ffff:") or ip.startswith("::FFFF:"):
        candidate = ip[7:]
        try:
            socket.inet_aton(candidate)
            return candidate
        except OSError:
            pass
    return ip


def _read_proc_net_tcp() -> list[dict]:
    entries = []
    for proc_file, is_v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(proc_file) as f:
                lines = f.readlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local  = parts[1]
            remote = parts[2]
            inode  = parts[9]
            try:
                local_ip_hex,  local_port_hex  = local.rsplit(":", 1)
                remote_ip_hex, remote_port_hex = remote.rsplit(":", 1)
                if is_v6:
                    local_ip  = _hex_to_ip6(local_ip_hex)
                    remote_ip = _hex_to_ip6(remote_ip_hex)
                else:
                    local_ip  = _hex_to_ip(local_ip_hex)
                    remote_ip = _hex_to_ip(remote_ip_hex)
                entries.append({
                    "local":       f"{local_ip}:{int(local_port_hex, 16)}",
                    "remote_ip":   remote_ip,
                    "remote_port": int(remote_port_hex, 16),
                    "inode":       inode,
                })
            except Exception:
                continue
    return entries


def _build_inode_map() -> dict[str, tuple[int, str]]:
    """Scan /proc once to build inode → (pid, name) for all socket fds.

    O(processes × fds) total instead of O(connections × processes × fds)
    when looking up multiple inodes from the same snapshot.
    """
    inode_map: dict[str, tuple[int, str]] = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            comm_path = f"/proc/{pid}/comm"
            fd_dir    = f"/proc/{pid}/fd"
            with open(comm_path) as f:
                name = f.read().strip()
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link.startswith("socket:["):
                        inode_map[link[8:-1]] = (int(pid), name)
                except (PermissionError, FileNotFoundError):
                    pass
        except (PermissionError, FileNotFoundError):
            continue
    return inode_map


class ProcessNetworkMonitor:
    def __init__(self, known_processes: set[str] | None = None,
                 whitelist: list[str] | None = None):
        self._known = known_processes or set()
        self._whitelist = set(whitelist or [])
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._helper = None

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus = bus
        self._helper = helper
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def snapshot(self) -> list[Connection]:
        # With the privileged helper we get every process's connections
        # (including root daemons); an unprivileged /proc scan only sees the
        # current user's, silently missing connections owned by others.
        if self._helper and self._helper.is_connected():
            conns = await self._helper.proc_conns()
            if conns is not None:
                return [
                    Connection(
                        pid=c["pid"], process=c["process"],
                        local_addr=c["local"],
                        remote_addr=f"{c['remote_ip']}:{c['remote_port']}",
                        remote_ip=c["remote_ip"], remote_port=c["remote_port"],
                    )
                    for c in conns
                ]
        return await asyncio.to_thread(self._build_snapshot)

    def _build_snapshot(self) -> list[Connection]:
        inode_map = _build_inode_map()  # single /proc scan for all pids
        conns = []
        for entry in _read_proc_net_tcp():
            rip = _unwrap_mapped(entry["remote_ip"])
            if rip in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
                continue
            result = inode_map.get(entry["inode"])
            if result:
                pid, name = result
                conns.append(Connection(
                    pid=pid,
                    process=name,
                    local_addr=entry["local"],
                    remote_addr=f"{rip}:{entry['remote_port']}",
                    remote_ip=rip,
                    remote_port=entry["remote_port"],
                ))
        return conns

    _NORMAL_PORTS = {80, 443, 8080, 8443, 53, 22, 5353, 8888, 1194, 51820}

    async def _monitor(self) -> None:
        seen: set[tuple] = set()
        while True:
            await asyncio.sleep(10)
            conns = await self.snapshot()
            for conn in conns:
                if conn.remote_ip in self._whitelist:
                    continue
                if self._known and conn.process not in self._known:
                    if conn.remote_port in self._NORMAL_PORTS:
                        continue
                    key = (conn.process, conn.remote_ip, conn.remote_port)
                    if key in seen:
                        continue
                    seen.add(key)
                    await self._bus.emit(Event(
                        type=EventType.UNKNOWN_PROCESS,
                        level=ThreatLevel.SUSPICIOUS,
                        message=f"Unknown process connected externally: "
                                f"{conn.process} (PID {conn.pid}) → {conn.remote_addr}",
                        data={"process": conn.process, "pid": conn.pid,
                              "remote": conn.remote_addr},
                    ))
            # Prune seen set to prevent unbounded memory growth over long sessions
            if len(seen) > _SEEN_MAX:
                seen.clear()
