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
import shutil
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
_IP_RE     = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')
# firewall-cmd flags that Maze Guard is allowed to use via the helper.
# Anything else (panic-on, --direct, --remove-service=ssh, ...) is rejected,
# so a maze-group member can't brick the system through the socket.
_FWC_SAFE_FLAGS = {
    "--permanent", "--zone", "--add-rich-rule", "--remove-rich-rule",
    "--list-rich-rules", "--list-all", "--reload",
    "--get-default-zone",
    # Zone-target modification: used by incoming-block toggle to drop
    # uninvited traffic while still honouring allowed services in the zone
    # (e.g. kdeconnect). Only these two values are permitted.
    "--set-target=DROP", "--set-target=default",
}
# NOT allowed, deliberately: --set-default-zone. Maze Guard never sets the
# default zone — it operates on whatever zone is already active — but leaving
# the flag permitted meant anything running as a maze-group member could say
# `--set-default-zone trusted` and switch the host to accept-everything. A
# full firewall bypass that no feature needed.
# Optional logging clause a block rule may carry. Every auto-block is worth an
# audit trail in the kernel log, but the prefix is pinned to MAZE-* and the rate
# is capped so a client cannot turn this into a log-flood DoS.
_LOG_CLAUSE = r'(?:log prefix=MAZE-[A-Z]{1,10} level=info limit value=[1-9]/m )?'
# Rich rules are matched in FULL against these patterns (never by prefix, which
# would let a client append arbitrary actions like accept/forward-port/masquerade
# after a legal-looking source= clause). The action is locked to `drop`, and an
# all-traffic source (0.0.0.0/0, ::/0) is rejected so a maze-group member can
# neither redirect traffic nor black-hole the whole system through this channel.
_FWC_RULE_RES = (
    re.compile(
        r'^rule family=ipv4 source address='
        r'(?!0\.0\.0\.0(/0)?(?: |$))'          # forbid catch-all source
        r'\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})? ' + _LOG_CLAUSE + r'drop$'
    ),
    re.compile(
        r'^rule family=ipv6 source address='
        r'(?!::(/0)?(?: |$))'                  # forbid catch-all source
        r'[0-9a-fA-F:]{2,39}(?:/\d{1,3})? ' + _LOG_CLAUSE + r'drop$'
    ),
    re.compile(
        r'^rule family=ipv[46] port port=\d{1,5} protocol=(?:tcp|udp) '
        + _LOG_CLAUSE + r'drop$'
    ),
)
# Zone names accepted after --zone. The full built-in set is allowed because
# this only says *which* zone a rule applies to, and the host's default zone
# could legitimately be any of them. What made "trusted" dangerous was
# --set-default-zone, which could switch the machine into it; with that flag
# gone, naming a zone here grants nothing beyond adding drop rules to it.
_FWC_SAFE_ZONES  = ("public", "home", "drop", "block", "internal", "work",
                    "trusted", "external", "dmz")
_SYSCTL_ALLOWED = {
    "net.ipv4.ip_default_ttl",
    "net.ipv4.tcp_window_scaling",
}
# systemd units the helper may stop/start (hostname/mDNS hiding).
_SVC_ALLOWED    = {"avahi-daemon"}
_SVC_ACTIONS    = {"stop", "start", "is-active"}
# The firewall backend gets its own command (`fw_service`) rather than riding on
# the generic `svc` one: stopping it is the single most consequential thing a
# maze-group member can ask for, so it is spelled out here, kept to one unit and
# a fixed action set, and logged on every call.
_FW_UNIT        = "firewalld"
_FW_SVC_ACTIONS = {"start", "stop", "restart", "is-active", "is-enabled",
                   "enable", "disable"}

# ── Consent for protection-disabling requests ────────────────────────────────
# Adding protection is unauthenticated; removing it is not. See
# packaging/org.mazeguard.policy for the prompt text and polkit defaults.
_POLKIT_ACTION  = "org.mazeguard.disable-protection"
_AUTH_TIMEOUT   = 60.0     # the user needs time to read the prompt and type
# firewall-cmd arguments that reduce protection, and therefore need consent.
# Removing a rule is judged by WHAT is being removed, not that a removal is
# happening: dropping a *source address* rule unblocks an attacker, while
# dropping a *port* rule merely undoes Maze Guard's own mDNS/NetBIOS stealth —
# which the app does itself on every profile change, and which exposes the user
# to nothing. Gating both would have put a password prompt in front of an
# ordinary profile switch.
_FWC_LOWERS_SHIELD = "--set-target=default"
_FWC_REMOVE_RULE = "--remove-rich-rule"


def _needs_consent(args: list[str]) -> str:
    """Describe why this command needs authorisation, or "" if it does not."""
    if _FWC_LOWERS_SHIELD in args:
        return "lower the incoming-traffic shield"
    if _FWC_REMOVE_RULE in args:
        rule = args[args.index(_FWC_REMOVE_RULE) + 1] if \
            args.index(_FWC_REMOVE_RULE) + 1 < len(args) else ""
        if "source address=" in rule:
            return "remove a block on an attacker"
    return ""


SO_PEERCRED = 17

_clients: list[asyncio.StreamWriter] = []
_loop: asyncio.AbstractEventLoop | None = None
_owner_uid: int = 0


def _peer_cred(writer: asyncio.StreamWriter) -> tuple[int, int]:
    """(pid, uid) of the connected client, or (-1, -1) if it cannot be read."""
    try:
        sock = writer.get_extra_info('socket')
        cred = sock.getsockopt(_socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
        pid, uid, _ = struct.unpack('3i', cred)
        return pid, uid
    except Exception:
        return -1, -1


def _peer_uid(writer: asyncio.StreamWriter) -> int:
    return _peer_cred(writer)[1]


def _peer_name(writer: asyncio.StreamWriter) -> str:
    """Describe the caller for the audit log: pid, uid and the program name.

    Membership of the `maze` group is what grants access, so every process
    running as the desktop user qualifies — including one that got there
    without the user's knowledge. Recording *which* program asked is what makes
    an abusive caller identifiable after the fact.
    """
    pid, uid = _peer_cred(writer) if writer is not None else (-1, -1)
    comm = "?"
    try:
        comm = Path(f"/proc/{pid}/comm").read_text().strip()
    except Exception:
        pass
    return f"pid={pid} uid={uid} comm={comm}"


async def _authorized(writer: asyncio.StreamWriter, what: str) -> tuple[bool, str]:
    """Ask polkit whether this caller may turn a protection off.

    The socket's group check answers "is this the desktop user?", which is not
    the question that matters for a destructive request — anything running as
    that user, invited or not, passes it. polkit asks the user directly, through
    a dialog the requesting program has no way to answer on their behalf.

    The subject is pinned as pid,start-time,uid rather than a bare pid: a pid
    alone can be recycled between the check and the act, letting an attacker
    inherit somebody else's authorisation.
    """
    pid, uid = _peer_cred(writer)
    if uid == 0:
        return True, ""                      # root already has every privilege
    if pid <= 0:
        return False, "could not identify the calling process"
    if shutil.which("pkcheck") is None:
        return False, ("polkit is not installed, so this cannot be authorised "
                       "here — use: sudo systemctl stop firewalld")

    start = _proc_start_time(pid)
    if start is None:
        return False, "could not identify the calling process"

    r = await _run(
        ["pkcheck", "--action-id", _POLKIT_ACTION,
         "--process", f"{pid},{start},{uid}", "--allow-user-interaction"],
        timeout=_AUTH_TIMEOUT,
    )
    if r.returncode == 0:
        _audit(writer, f"authorised: {what}")
        return True, ""
    _audit(writer, f"DENIED (not authorised): {what}")
    err = r.stderr.strip()
    if "not registered" in err:
        # The daemon was updated but its polkit action was not installed. Say
        # that plainly — the raw GDBus error sends people looking in the wrong
        # place entirely.
        return False, ("the Maze Guard polkit action is not installed "
                       "(org.mazeguard.policy) — reinstall the package")
    return False, (err.splitlines()[0] if err else "authorisation was declined")


def _proc_start_time(pid: int) -> int | None:
    """Field 22 of /proc/<pid>/stat — the process's start time in clock ticks.

    Parsed from after the last ')' because the second field is the executable
    name, which may itself contain spaces and parentheses.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return int(stat[stat.rindex(")") + 2:].split()[19])
    except Exception:
        return None


def _audit(writer: asyncio.StreamWriter, what: str) -> None:
    """Record a state-changing request in the journal.

    Read-only queries are not logged — they are constant background noise from
    the UI's own polling, and burying the three lines that matter under them
    would defeat the purpose.
    """
    print(f"maze-helper: {what} [{_peer_name(writer)}]",
          file=sys.stderr, flush=True)


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
      not exist, only root is allowed — the socket is root-only (0600) in that
      case, so this simply keeps the in-process check consistent with it.
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
        # No maze group exists → no non-root principal is authorised. The
        # socket is already root-only (0600) in this case; denying here keeps
        # the in-process check and the file permissions in agreement instead
        # of silently trusting every local uid.
        return False
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


# BPF program for the capture thread. Deliberately narrow: everything captured
# here is pushed over the socket and re-examined in the GUI process, so a filter
# that admits ordinary bulk traffic (established TCP, QUIC, DNS) would cost far
# more than it detects. What is admitted, and why:
#
#   arp                     — poisoning (replies) and host discovery (requests)
#   icmp echo/timestamp/mask— ping sweeps and the older recon probe types
#   tcp without ACK         — SYN scans plus the stealth family (FIN, NULL,
#                             XMAS): a scanner has no connection to ACK, so
#                             dropping ACK-bearing packets removes essentially
#                             all normal traffic while keeping every probe
#   udp 67/68               — DHCP, for rogue-server detection
_SNIFF_BPF = (
    "arp"
    " or (icmp and (icmp[icmptype] = 8 or icmp[icmptype] = 13"
    " or icmp[icmptype] = 17))"
    " or (tcp and tcp[tcpflags] & tcp-ack = 0 and"
    " (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-push|tcp-urg) != 0"
    " or tcp[tcpflags] = 0))"
    " or (udp and (port 67 or port 68))"
)
# Ceiling on packets forwarded to clients per second. A scan can arrive far
# faster than any of this is worth reporting individually; past the ceiling we
# count instead of forward and publish the count, so the GUI still learns the
# true volume without the socket becoming the bottleneck.
_PUSH_RATE_LIMIT = 400

# DHCP message types we care about: only a server sends OFFER or ACK, so seeing
# one from an unexpected address is what identifies a rogue DHCP server.
_DHCP_TYPES = {"discover": 1, "offer": 2, "request": 3, "decline": 4,
               "ack": 5, "nak": 6, "release": 7, "inform": 8}


class _PushLimiter:
    """Token-bucket-ish limiter over one-second windows."""

    def __init__(self, per_second: int):
        self._per_second = per_second
        self._window = 0.0
        self._sent = 0
        self._dropped = 0

    def allow(self) -> bool:
        now = time.monotonic()
        if now - self._window >= 1.0:
            if self._dropped:
                _push({"event": "throttled", "dropped": self._dropped})
                self._dropped = 0
            self._window = now
            self._sent = 0
        if self._sent < self._per_second:
            self._sent += 1
            return True
        self._dropped += 1
        return False


def _tcp_flag_str(flags) -> str:
    """Normalise scapy's flag field to a stable short string ('S', 'FPU', '')."""
    try:
        return str(flags)
    except Exception:
        return ""


def _sniff_once(iface: str, limiter: "_PushLimiter", stop_after: int) -> None:
    from scapy.all import ARP, DHCP, ICMP, IP, TCP, sniff

    own_ips: set[str] = _get_iface_ips(iface)
    own_ips_refreshed_at: float = time.monotonic()

    def handle(pkt):
        nonlocal own_ips, own_ips_refreshed_at
        # Refresh every 60 s — replace (not update) so old-network IPs evict.
        now = time.monotonic()
        if now - own_ips_refreshed_at >= 60:
            own_ips = _get_iface_ips(iface)
            own_ips_refreshed_at = now

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.psrc in own_ips:
                return
            if not limiter.allow():
                return
            # op 1 = who-has (discovery), op 2 = is-at (the spoofing vector).
            _push({"event": "arp", "op": int(arp.op), "src": arp.psrc,
                   "mac": arp.hwsrc, "dst": arp.pdst})
            return

        if not pkt.haslayer(IP):
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        if src in own_ips:          # our own probes are not attacks on us
            return

        if pkt.haslayer(TCP):
            if not limiter.allow():
                return
            tcp = pkt[TCP]
            _push({"event": "tcp", "src": src, "dst": dst,
                   "sport": int(tcp.sport), "dport": int(tcp.dport),
                   "flags": _tcp_flag_str(tcp.flags), "ttl": int(pkt[IP].ttl),
                   "win": int(tcp.window)})
        elif pkt.haslayer(ICMP):
            if not limiter.allow():
                return
            _push({"event": "icmp", "src": src, "dst": dst,
                   "type": int(pkt[ICMP].type), "ttl": int(pkt[IP].ttl)})
        elif pkt.haslayer(DHCP):
            mtype = 0
            server = ""
            for opt in pkt[DHCP].options:
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                if opt[0] == "message-type":
                    # scapy hands this back as a number when it parsed the
                    # packet off the wire, but as a name ("offer") when the
                    # option was set symbolically. Accept either.
                    mtype = _DHCP_TYPES.get(str(opt[1]).lower(), 0) \
                        if not isinstance(opt[1], int) else opt[1]
                elif opt[0] == "server_id":
                    server = str(opt[1])
            # 2 = OFFER, 5 = ACK: only a DHCP *server* sends these.
            if mtype in (2, 5) and limiter.allow():
                _push({"event": "dhcp", "src": src, "mtype": mtype,
                       "server": server,
                       "mac": pkt.src if hasattr(pkt, "src") else ""})

    sniff(iface=iface, filter=_SNIFF_BPF, prn=handle, store=False,
          timeout=stop_after)


def _sniff_thread(iface: str) -> None:
    """Capture forever, surviving link changes.

    The capture is run in bounded slices rather than one endless call so the
    interface can be re-resolved between them. Without that, a WiFi reconnect or
    a switch to Ethernet left the helper sniffing a dead interface and the GUI
    silently blind — the failure mode looked exactly like "no attacks today".
    """
    limiter = _PushLimiter(_PUSH_RATE_LIMIT)
    current = iface
    backoff = 1.0
    while True:
        try:
            _sniff_once(current, limiter, stop_after=60)
            backoff = 1.0
        except Exception as exc:
            _push({"event": "error", "msg": f"capture on {current}: {exc}"})
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
        # Re-resolve between slices so a new link is picked up automatically.
        try:
            resolved = _resolve_iface(current)
            if resolved and resolved != current:
                _push({"event": "iface", "iface": resolved, "was": current})
                current = resolved
        except Exception:
            pass


class _Completed:
    """Stand-in for CompletedProcess when a command had to be given up on."""

    def __init__(self, returncode: int = 124, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


async def _run(args: list[str], timeout: float = 10.0):
    """Run a command off the event loop, with a hard time limit.

    Both halves matter. `subprocess.run` called straight from a coroutine
    blocks the *entire* helper — one slow command and no other client request,
    not even a ping, gets answered. And `firewall-cmd` is not reliably fast: with
    firewalld stopped it sits in D-Bus activation until that times out, so a UI
    polling the rule list every few seconds could wedge the daemon indefinitely.
    Everything the helper shells out to goes through here.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(subprocess.run, args,
                              capture_output=True, text=True),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, TimeoutError):
        print(f"maze-helper: timed out after {timeout}s: {' '.join(args)}",
              file=sys.stderr, flush=True)
        return _Completed(stderr=f"timed out after {timeout}s")
    except Exception as exc:
        return _Completed(stderr=str(exc))


async def _firewalld_active() -> bool:
    """Cheap, D-Bus-free check that firewalld is up.

    Guards every firewall-cmd call: asking a stopped firewalld anything is not
    an error worth waiting on, it is a question with a known answer.
    """
    r = await _run(["systemctl", "is-active", _FW_UNIT], timeout=5.0)
    return r.stdout.strip() == "active"


async def _dispatch(req: dict, writer: asyncio.StreamWriter) -> dict:
    """Execute one request and return its response envelope."""
    cmd    = req.get("cmd", "")
    req_id = req.get("id", 0)
    resp: dict = {"id": req_id, "ok": False}

    if cmd == "ping":
        resp["ok"] = True

    elif cmd == "fw_list_all":
        if not await _firewalld_active():
            resp.update(ok=True, data="", err="firewalld is not running")
        else:
            r = await _run(["firewall-cmd", "--list-all"])
            resp.update(ok=(r.returncode == 0 or r.returncode == 252),
                        data=r.stdout)

    elif cmd == "fw_cmd":
        # Validate: only allow a curated whitelist of firewall-cmd flags
        # and rule strings. Anything else (panic-on, --direct, etc.)
        # is rejected so a maze-group member can't brick the system.
        args = req.get("args", [])
        if not (isinstance(args, list) and len(args) >= 1
                and args[0] == "firewall-cmd"):
            resp["err"] = "fw_cmd requires firewall-cmd args"
        else:
            bad = False
            for a in args[1:]:
                if a in _FWC_SAFE_FLAGS:
                    continue
                if a in _FWC_SAFE_ZONES:
                    continue
                if any(rx.match(a) for rx in _FWC_RULE_RES):
                    continue
                bad = True
                resp["err"] = f"disallowed firewall-cmd argument: {a}"
                break
            if not bad:
                _audit(writer, f"fw_cmd {' '.join(args[1:])}")
                consent_for = _needs_consent(args)
                allowed, why = ((True, "") if not consent_for else
                                await _authorized(writer, consent_for))
                if not allowed:
                    resp["err"] = why
                elif not await _firewalld_active():
                    resp["err"] = "firewalld is not running"
                else:
                    r = await _run(args, timeout=20.0)
                    resp.update(ok=(r.returncode == 0 or r.returncode == 252),
                                err=r.stderr.strip())

    elif cmd == "fw_list":
        import re as _re
        data = {"ips": [], "ports_tcp": [], "ports_udp": []}
        r = (await _run(["firewall-cmd", "--list-rich-rules"])
             if await _firewalld_active() else _Completed())
        if r.returncode == 0 or r.returncode == 252:
            ip_re = _re.compile(r'source address="?([^"\s]+)"?')
            port_re = _re.compile(r'port port="?(\d+)"? protocol="?(tcp|udp)"?')
            for line in r.stdout.splitlines():
                m = ip_re.search(line)
                if m:
                    data["ips"].append(m.group(1))
                    continue
                m = port_re.search(line)
                if m and int(m.group(1)) not in data[f"ports_{m.group(2)}"]:
                    data[f"ports_{m.group(2)}"].append(int(m.group(1)))
        resp.update(ok=True, data=data)

    elif cmd == "fw_state":
        # One round-trip snapshot of everything the UI needs to render
        # an honest firewall widget. Reading these separately from the
        # GUI raced against itself and produced buttons whose label and
        # behaviour disagreed.
        state = {"installed": False, "running": False, "enabled": False,
                 "zone": "", "target": "", "panic": False}
        try:
            r = await _run(["systemctl", "is-active", _FW_UNIT], timeout=5.0)
            state["installed"] = r.stdout.strip() != "" or r.returncode in (0, 3)
            state["running"] = r.stdout.strip() == "active"
            r = await _run(["systemctl", "is-enabled", _FW_UNIT], timeout=5.0)
            state["enabled"] = r.stdout.strip() == "enabled"
            if state["running"]:
                r = await _run(["firewall-cmd", "--get-default-zone"])
                state["zone"] = r.stdout.strip()
                r = await _run(["firewall-cmd", "--list-all"])
                for line in r.stdout.splitlines():
                    s = line.strip().lower()
                    if s.startswith("target:"):
                        state["target"] = s.split(":", 1)[1].strip()
                        break
                r = await _run(["firewall-cmd", "--query-panic"])
                state["panic"] = r.stdout.strip() == "yes"
        except Exception as e:
            resp["err"] = str(e)
        resp.update(ok=True, data=state)

    elif cmd == "fw_service":
        action = req.get("action", "")
        if action not in _FW_SVC_ACTIONS:
            resp["err"] = "action not allowed"
        else:
            query = action.startswith("is-")
            if not query:
                _audit(writer, f"fw_service {action} {_FW_UNIT}")
            allowed, why = ((True, "") if action not in ("stop", "disable")
                            else await _authorized(writer,
                                                   f"{action} the firewall"))
            if not allowed:
                resp["err"] = why
            else:
                r = await _run(["systemctl", action, _FW_UNIT], timeout=45.0)
                # is-active/is-enabled report status through their exit code;
                # a non-zero there means "inactive", not "command failed".
                resp.update(ok=(query or r.returncode == 0),
                            data=r.stdout.strip(), err=r.stderr.strip())

    elif cmd == "svc":
        action = req.get("action", "")
        unit   = req.get("unit", "")
        if unit not in _SVC_ALLOWED or action not in _SVC_ACTIONS:
            resp["err"] = "service or action not allowed"
        else:
            if action != "is-active":
                _audit(writer, f"svc {action} {unit}")
            r = await _run(["systemctl", action, unit], timeout=30.0)
            # is-active returns non-zero when inactive — that's not an error,
            # the caller inspects `data` instead.
            resp.update(ok=(action == "is-active" or r.returncode == 0),
                        data=r.stdout.strip(), err=r.stderr.strip())

    elif cmd == "proc_conns":
        # Build the full connection→process map from root so the GUI can
        # attribute connections owned by other users (incl. root daemons),
        # which an unprivileged /proc scan cannot see.
        def _collect() -> list[dict]:
            from maze.protection.process_map import (
                _read_proc_net_tcp, _build_inode_map, _unwrap_mapped)
            inode_map = _build_inode_map()
            conns = []
            for entry in _read_proc_net_tcp():
                rip = _unwrap_mapped(entry["remote_ip"])
                if rip in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
                    continue
                if rip.startswith("127."):
                    continue
                res = inode_map.get(entry["inode"])
                if not res:
                    continue
                pid, name, exe, cmdline = res
                conns.append({
                    "pid": pid, "process": name,
                    "exe": exe, "cmdline": cmdline,
                    "local": entry["local"], "remote_ip": rip,
                    "remote_port": entry["remote_port"],
                })
            return conns

        # Walking every /proc/<pid>/fd is not free on a busy machine, and the
        # GUI asks for this on a timer — off the event loop it goes.
        try:
            resp.update(ok=True, data=await asyncio.wait_for(
                asyncio.to_thread(_collect), timeout=15.0))
        except Exception as e:
            resp["err"] = str(e)

    elif cmd == "sysctl_get":
        key = req.get("key", "")
        if key not in _SYSCTL_ALLOWED:
            resp["err"] = "disallowed sysctl key"
        else:
            r = await _run(["sysctl", "-n", key], timeout=5.0)
            resp.update(ok=r.returncode == 0, data=r.stdout.strip())

    elif cmd == "sysctl_set":
        key   = req.get("key", "")
        value = str(req.get("value", ""))
        if key not in _SYSCTL_ALLOWED:
            resp["err"] = "disallowed sysctl key"
        elif not re.match(r'^\d+$', value):
            resp["err"] = "invalid sysctl value (digits only)"
        else:
            _audit(writer, f"sysctl {key}={value}")
            r = await _run(["sysctl", "-w", f"{key}={value}"], timeout=5.0)
            resp.update(ok=r.returncode == 0, err=r.stderr.strip())

    else:
        resp["err"] = f"unknown command: {cmd}"

    return resp


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # Verify the caller is allowed (maze group member / invoking user / root)
    if not _peer_allowed(writer):
        writer.close()
        return

    _clients.append(writer)
    # Requests run concurrently, but only a few at a time. Answering them one
    # after another meant a single slow command (a systemctl start, a firewalld
    # that has gone away) stalled every later request on the connection, and the
    # GUI — which polls state on a timer — kept queueing more behind it. The cap
    # keeps a client from spawning unbounded work.
    gate = asyncio.Semaphore(4)
    pending: set[asyncio.Task] = set()

    async def serve(req: dict) -> None:
        async with gate:
            try:
                resp = await _dispatch(req, writer)
            except Exception as exc:
                resp = {"id": req.get("id", 0), "ok": False, "err": str(exc)}
            try:
                writer.write((json.dumps(resp) + "\n").encode())
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass

    try:
        async for raw in reader:
            line = raw.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            task = asyncio.create_task(serve(req))
            pending.add(task)
            task.add_done_callback(pending.discard)

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        for task in list(pending):
            task.cancel()
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
