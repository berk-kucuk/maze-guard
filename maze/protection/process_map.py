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
    exe: str = ""       # basename of /proc/<pid>/exe (real binary), if readable
    cmdline: str = ""   # full command line — reveals the app behind renamed comm


def _proc_cmdline(pid) -> str:
    """Full command line of ``pid`` (NUL-separated args joined by spaces).

    Readable for one's own processes and by root for all — unlike comm it is
    NOT renamed by multi-process apps, so it still carries the real identity
    (e.g. a Bitwarden Electron child shows /usr/lib/bitwarden/app.asar even
    though its comm is just "electron")."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _readlink_exe(pid) -> str:
    """Basename of the process's real executable, or "" if unreadable.

    Sandboxed children (Chromium/Electron) may hide their exe, so callers must
    treat "" as "unknown" and fall back to cmdline-based identity."""
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        return os.path.basename(target.split(" (deleted)")[0])
    except Exception:
        return ""


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


def _build_inode_map() -> dict[str, tuple[int, str, str, str]]:
    """Scan /proc once to build inode → (pid, comm, exe, cmdline) for socket fds.

    O(processes × fds) total instead of O(connections × processes × fds)
    when looking up multiple inodes from the same snapshot. exe/cmdline are
    resolved only for processes that actually own sockets.
    """
    inode_map: dict[str, tuple[int, str, str, str]] = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            fd_dir = f"/proc/{pid}/fd"
            sock_inodes = []
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link.startswith("socket:["):
                        sock_inodes.append(link[8:-1])
                except (PermissionError, FileNotFoundError):
                    pass
            if not sock_inodes:
                continue
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
            exe     = _readlink_exe(pid)
            cmdline = _proc_cmdline(pid)
            for inode in sock_inodes:
                inode_map[inode] = (int(pid), name, exe, cmdline)
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
                        exe=c.get("exe", ""), cmdline=c.get("cmdline", ""),
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
            if rip.startswith("127."):  # loopback — not an external connection
                continue
            result = inode_map.get(entry["inode"])
            if result:
                pid, name, exe, cmdline = result
                conns.append(Connection(
                    pid=pid,
                    process=name,
                    local_addr=entry["local"],
                    remote_addr=f"{rip}:{entry['remote_port']}",
                    remote_ip=rip,
                    remote_port=entry["remote_port"],
                    exe=exe,
                    cmdline=cmdline,
                ))
        return conns

    _NORMAL_PORTS = {
        80, 443, 8080, 8443, 53, 22, 5353, 8888, 1194, 51820,
        21, 25, 587, 465, 993, 995, 143, 110, 123, 389, 636, 853,
        3000, 5000, 8000, 8081, 9090, 9418, 9092, 3478, 5349,
        5222, 5269, 6697, 64738, 5060, 5061,
    }

    def _is_known(self, conn: Connection) -> bool:
        """Whether ``conn`` belongs to a known/whitelisted process.

        Matches known-process keys against three identity sources, so that
        multi-process apps whose comm is renamed ("Socket Process", "electron",
        "Isolated Web Co") are still recognised:
          • comm            (conn.process)
          • exe basename    (conn.exe, when the sandbox lets us read it)
          • every path component of the cmdline — this is what catches an
            Electron app by its install dir, e.g.
            /usr/lib/bitwarden/app.asar → component "bitwarden".
        Matching is case-insensitive; a key matches a candidate that equals it
        or begins with "<key>-" / "<key>." (covers firefox-esr, chrome-sandbox,
        chromium-browser) without over-matching unrelated names (wg vs wget).
        """
        candidates: set[str] = set()
        if conn.process:
            candidates.add(conn.process.lower())
        if conn.exe:
            candidates.add(conn.exe.lower())
        for tok in (conn.cmdline or "").lower().split():
            for part in tok.split("/"):
                if part:
                    candidates.add(part)
        for k in self._known:
            kl = k.lower()
            for c in candidates:
                if c == kl or c.startswith(kl + "-") or c.startswith(kl + "."):
                    return True
        return False

    async def _monitor(self) -> None:
        seen: set[tuple] = set()
        while True:
            await asyncio.sleep(10)
            conns = await self.snapshot()
            for conn in conns:
                if conn.remote_ip in self._whitelist:
                    continue
                if self._known and not self._is_known(conn):
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
            if len(seen) > _SEEN_MAX:
                items = list(seen)
                seen.clear()
                seen.update(items[-_SEEN_MAX // 2:])
