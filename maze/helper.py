"""
Maze Guard privileged helper.

Runs as root — normally as a systemd system service (daemon mode) so the GUI
never has to handle a sudo password. Access to its control socket is gated by
the `maze` group (members can connect; everyone else is rejected by both file
permissions and an in-process peer-credential check).
"""
import asyncio
import json
import os
import re
import signal
import time
import socket as _socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

# Fixed, well-known socket living under /run (tmpfs, cleared on reboot).
_SOCK_DIR  = "/run/maze"
_SOCK_PATH = "/run/maze/maze.sock"
_GROUP     = "maze"
_MAC_RE    = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
_IP_RE     = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')
_IFACE_RE  = re.compile(r'^[a-zA-Z0-9_\-]{1,15}$')
_NFT_OPS        = {"add", "delete", "list", "flush", "get"}
_SYSCTL_ALLOWED = {
    "net.ipv4.ip_default_ttl",
    "net.ipv4.tcp_window_scaling",
}
# nftables tables the helper is allowed to touch. Everything else on the system
# firewall is off-limits even to maze-group members.
_FW_TABLES      = {"maze_firewall", "maze_shield"}
# systemd units the helper may stop/start (hostname/mDNS hiding).
_SVC_ALLOWED    = {"avahi-daemon"}
_SVC_ACTIONS    = {"stop", "start", "is-active"}
SO_PEERCRED = 17


def _nft_table_allowed(args: list) -> bool:
    """True if an `nft ... inet <table> ...` command targets only an allowed table.

    Commands that don't name a table after `inet` (e.g. `nft list ruleset`) are
    rejected here and must go through dedicated read-only handlers instead.
    """
    try:
        idx = args.index("inet")
    except ValueError:
        return False
    if idx + 1 >= len(args):
        return False
    return args[idx + 1] in _FW_TABLES

_clients: list[asyncio.StreamWriter] = []
_loop: asyncio.AbstractEventLoop | None = None
_owner_uid: int = 0


def _peer_uid(writer: asyncio.StreamWriter) -> int:
    try:
        sock = writer.get_extra_info('socket')
        cred = sock.getsockopt(_socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
        _, uid, _ = struct.unpack('3i', cred)
        return uid
    except Exception:
        return -1


def _maze_gid() -> int | None:
    try:
        import grp
        return grp.getgrnam(_GROUP).gr_gid
    except Exception:
        return None


def _peer_allowed(writer: asyncio.StreamWriter) -> bool:
    """
    Decide whether a connecting client may use the helper.

    • Legacy sudo mode (SUDO_UID set): only the invoking user (or root).
    • Daemon mode: any member of the `maze` group (or root). If the group does
      not exist, fall back to allowing — the socket's file permissions already
      gate access in that case.
    """
    uid = _peer_uid(writer)
    if uid < 0:
        return False
    if uid == 0:
        return True
    if _owner_uid:                       # launched via sudo by a specific user
        return uid == _owner_uid
    gid = _maze_gid()
    if gid is None:
        return True
    try:
        import pwd
        pw = pwd.getpwuid(uid)
        return gid in os.getgrouplist(pw.pw_name, pw.pw_gid)
    except Exception:
        return False


def _push(event: dict) -> None:
    if not _loop or not _clients:
        return
    data = (json.dumps(event) + "\n").encode()
    for w in list(_clients):
        try:
            _loop.call_soon_threadsafe(w.write, data)
        except Exception:
            pass


def _get_iface_ips(iface: str) -> set[str]:
    """Return all IPv4 addresses assigned to iface (to filter own SYN packets)."""
    import re as _re
    own: set[str] = set()
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface], text=True, timeout=3)
        for m in _re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)/', out):
            own.add(m.group(1))
    except Exception:
        pass
    return own


def _sniff_thread(iface: str) -> None:
    try:
        from scapy.all import ARP, IP, TCP, sniff

        own_ips: set[str] = _get_iface_ips(iface)
        own_ips_refreshed_at: float = time.monotonic()

        def handle(pkt):
            nonlocal own_ips, own_ips_refreshed_at
            # Refresh every 60 s — replace (not update) so old-network IPs evict.
            now = time.monotonic()
            if now - own_ips_refreshed_at >= 60:
                own_ips = _get_iface_ips(iface)
                own_ips_refreshed_at = now

            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                _push({"event": "arp", "src": pkt[ARP].psrc,
                       "mac": pkt[ARP].hwsrc, "dst": pkt[ARP].pdst})
            elif pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
                src = pkt[IP].src
                if src not in own_ips:  # skip own outgoing SYN packets
                    _push({"event": "syn", "src": src,
                           "dst": pkt[IP].dst, "dport": pkt[TCP].dport})

        sniff(iface=iface,
              filter="arp or (tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0)",
              prn=handle, store=False)
    except Exception as exc:
        _push({"event": "error", "msg": str(exc)})


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # Verify the caller is allowed (maze group member / invoking user / root)
    if not _peer_allowed(writer):
        writer.close()
        return

    _clients.append(writer)
    try:
        async for raw in reader:
            line = raw.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            cmd    = req.get("cmd", "")
            req_id = req.get("id", 0)
            resp: dict = {"id": req_id, "ok": False}

            if cmd == "ping":
                resp["ok"] = True

            elif cmd == "nft_list":
                r = subprocess.run(["nft", "list", "ruleset"],
                                   capture_output=True, text=True)
                resp.update(ok=r.returncode == 0, data=r.stdout)

            elif cmd == "nft_apply":
                rules = req.get("rules", "")
                if not isinstance(rules, str) or len(rules) > 65536:
                    resp["err"] = "invalid rules"
                else:
                    r = subprocess.run(["nft", "-f", "-"],
                                       input=rules, text=True, capture_output=True)
                    resp.update(ok=r.returncode == 0, err=r.stderr)

            elif cmd == "nft_delete":
                table = req.get("table", "")
                if table not in _FW_TABLES:
                    resp["err"] = "table not allowed"
                else:
                    r = subprocess.run(["nft", "delete", "table", "inet", table],
                                       capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0)

            elif cmd == "fw_cmd":
                args = req.get("args", [])
                if not (isinstance(args, list) and len(args) >= 2
                        and args[0] == "nft" and args[1] in _NFT_OPS):
                    resp["err"] = f"disallowed nft op: {args[1] if len(args) > 1 else '?'}"
                elif not _nft_table_allowed(args):
                    resp["err"] = "nft command targets a table outside maze scope"
                else:
                    r = subprocess.run(args, capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0, err=r.stderr.strip())

            elif cmd == "svc":
                action = req.get("action", "")
                unit   = req.get("unit", "")
                if unit not in _SVC_ALLOWED or action not in _SVC_ACTIONS:
                    resp["err"] = "service or action not allowed"
                else:
                    r = subprocess.run(["systemctl", action, unit],
                                       capture_output=True, text=True)
                    # is-active returns non-zero when inactive — that's not an error,
                    # the caller inspects `data` instead.
                    resp.update(ok=(action == "is-active" or r.returncode == 0),
                                data=r.stdout.strip(), err=r.stderr.strip())

            elif cmd == "proc_conns":
                # Build the full connection→process map from root so the GUI can
                # attribute connections owned by other users (incl. root daemons),
                # which an unprivileged /proc scan cannot see.
                try:
                    from maze.protection.process_map import (
                        _read_proc_net_tcp, _build_inode_map, _unwrap_mapped)
                    inode_map = _build_inode_map()
                    conns = []
                    for entry in _read_proc_net_tcp():
                        rip = _unwrap_mapped(entry["remote_ip"])
                        if rip in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
                            continue
                        res = inode_map.get(entry["inode"])
                        if not res:
                            continue
                        pid, name = res
                        conns.append({
                            "pid": pid, "process": name,
                            "local": entry["local"], "remote_ip": rip,
                            "remote_port": entry["remote_port"],
                        })
                    resp.update(ok=True, data=conns)
                except Exception as e:
                    resp["err"] = str(e)

            elif cmd == "fw_list":
                import re as _re
                data = {"ips": [], "ports_tcp": [], "ports_udp": []}
                r = subprocess.run(["nft", "list", "table", "inet", "maze_firewall"],
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    current_set = None
                    for ln in r.stdout.splitlines():
                        if "blocked_ips" in ln:       current_set = "ips"
                        elif "blocked_ports_tcp" in ln: current_set = "ports_tcp"
                        elif "blocked_ports_udp" in ln: current_set = "ports_udp"
                        m = _re.search(r"elements\s*=\s*\{([^}]+)\}", ln)
                        if m and current_set:
                            els = [e.strip() for e in m.group(1).split(",") if e.strip()]
                            if current_set == "ips":
                                data["ips"] = els
                            else:
                                data[current_set] = [int(p) for p in els if p.isdigit()]
                resp.update(ok=True, data=data)

            elif cmd == "sysctl_get":
                key = req.get("key", "")
                if key not in _SYSCTL_ALLOWED:
                    resp["err"] = "disallowed sysctl key"
                else:
                    r = subprocess.run(["sysctl", "-n", key],
                                       capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0, data=r.stdout.strip())

            elif cmd == "sysctl_set":
                key   = req.get("key", "")
                value = str(req.get("value", ""))
                if key not in _SYSCTL_ALLOWED:
                    resp["err"] = "disallowed sysctl key"
                elif not re.match(r'^\d+$', value):
                    resp["err"] = "invalid sysctl value (digits only)"
                else:
                    r = subprocess.run(["sysctl", "-w", f"{key}={value}"],
                                       capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0, err=r.stderr.strip())

            elif cmd == "set_mac":
                iface = req.get("iface", "")
                mac   = req.get("mac", "")
                if not _IFACE_RE.match(iface):
                    resp["err"] = "invalid interface name"
                elif not _MAC_RE.match(mac):
                    resp["err"] = "invalid MAC format"
                else:
                    try:
                        for args in (
                            ["ip", "link", "set", iface, "down"],
                            ["ip", "link", "set", iface, "address", mac],
                            ["ip", "link", "set", iface, "up"],
                        ):
                            subprocess.run(args, check=True, capture_output=True)
                        resp["ok"] = True
                    except subprocess.CalledProcessError as e:
                        resp["err"] = str(e)

            writer.write((json.dumps(resp) + "\n").encode())
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        if writer in _clients:
            _clients.remove(writer)
        writer.close()


def _setup_socket_perms(sock_path: str) -> None:
    """Make the socket reachable by the right principals, nobody else."""
    gid = _maze_gid()
    if gid is not None:
        # Daemon mode: root:maze, group can connect.
        try:
            os.chown(sock_path, 0, gid)
            os.chmod(sock_path, 0o660)
            return
        except Exception:
            pass
    # Legacy sudo mode: hand the socket to the invoking user only.
    uid = int(os.environ.get("SUDO_UID", "0"))
    sgid = int(os.environ.get("SUDO_GID", "0"))
    if uid:
        try:
            os.chown(sock_path, uid, sgid)
            os.chmod(sock_path, 0o600)
            return
        except Exception:
            pass
    # No group and not launched via sudo — leave it owner-only (root).
    os.chmod(sock_path, 0o600)


def _ensure_sock_dir() -> None:
    """Create /run/maze and make it traversable by the maze group."""
    Path(_SOCK_DIR).mkdir(parents=True, exist_ok=True)
    gid = _maze_gid()
    try:
        if gid is not None:
            os.chown(_SOCK_DIR, 0, gid)
            os.chmod(_SOCK_DIR, 0o750)
        else:
            os.chmod(_SOCK_DIR, 0o755)
    except Exception:
        pass


async def _serve(sock_path: str, iface: str) -> None:
    global _loop
    _loop = asyncio.get_running_loop()

    _ensure_sock_dir()
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    # Create socket with restrictive permissions from the start
    old_umask = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(_handle, sock_path)
    finally:
        os.umask(old_umask)

    _setup_socket_perms(sock_path)

    threading.Thread(target=_sniff_thread, args=(iface,), daemon=True).start()
    _loop.add_signal_handler(signal.SIGTERM, _loop.stop)

    async with server:
        await server.serve_forever()


def _resolve_iface(arg: str) -> str:
    """Use the given interface if it is up, otherwise auto-detect."""
    if arg:
        operstate = Path("/sys/class/net") / arg / "operstate"
        if operstate.exists() and operstate.read_text().strip() in ("up", "unknown"):
            return arg
    sys.path.insert(0, str(Path(__file__).parent.parent))
    try:
        from maze.utils.network_info import get_active_physical_interface
        detected = get_active_physical_interface()
        if detected != "—":
            return detected
    except Exception:
        pass
    return arg or "eth0"


if __name__ == "__main__":
    if os.getuid() != 0:
        print("maze helper must run as root", file=sys.stderr)
        sys.exit(1)

    # SUDO_UID is set only in legacy sudo mode; it is absent under systemd,
    # which is how the helper distinguishes daemon mode from sudo mode.
    _owner_uid = int(os.environ.get("SUDO_UID", "0"))
    iface = _resolve_iface(sys.argv[1] if len(sys.argv) > 1 else "")
    asyncio.run(_serve(_SOCK_PATH, iface))
