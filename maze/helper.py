"""
Maze Guard privileged helper.

Runs as root — normally as a systemd system service (daemon mode) so the GUI
never has to handle a sudo password. Access to its control socket is gated by
the `maze` group (members can connect; everyone else is rejected by both file
permissions and an in-process peer-credential check).
"""
import asyncio
import ipaddress
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
# after a legal-looking source= clause). The action is locked to `drop`.
#
# The two source-address patterns CAPTURE the address rather than trying to
# judge it. How much of the internet a CIDR block covers is a property of its
# mask, not of its text, and a regex cannot see that: the earlier version
# forbade the literal strings "0.0.0.0" and "::" and so accepted `1.2.3.4/0`
# — which is every address there is — along with `0.0.0.0/1` plus
# `128.0.0.0/1`, two rules that take the machine off the network. The mask is
# checked in _fwc_address_ok() below, with ipaddress doing the parsing.
_FWC_RULE_RES = (
    re.compile(
        r'^rule family=ipv4 source address='
        r'(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?) ' + _LOG_CLAUSE + r'drop$'
    ),
    re.compile(
        r'^rule family=ipv6 source address='
        r'([0-9a-fA-F:]{2,39}(?:/\d{1,3})?) ' + _LOG_CLAUSE + r'drop$'
    ),
    re.compile(
        r'^rule family=ipv[46] port port=\d{1,5} protocol=(?:tcp|udp) '
        + _LOG_CLAUSE + r'drop$'
    ),
    # Blocking by hardware address. An IP is a DHCP lease: a host that renews
    # it walks around an address block, and this application knows that better
    # than most since it says so on the Devices tab. A MAC is only meaningful
    # on the local segment — which is exactly the threat model — and the rule
    # is still locked to `drop` with no catch-all form to abuse.
    re.compile(
        r'^rule source mac=(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2} '
        + _LOG_CLAUSE + r'drop$'
    ),
)

# How broad a single source-address block may be.
#
# Maze Guard itself only ever blocks single hosts (/32, /128 — see
# protection/firewall.py::_ip_rule), but the Firewall tab lets someone type a
# CIDR by hand, and blocking 10.0.0.0/8 or 192.168.0.0/16 is a legitimate thing
# to want. What must not be reachable is the handful of rules that black-hole
# the machine: at /8 it takes 256 of them to cover IPv4 and the first one
# already breaks the user's own connection visibly, whereas /0 and /1 did it in
# one or two, silently, and permanently (--permanent), while UNDOING it needs
# the polkit admin prompt that _needs_consent puts in front of
# --remove-rich-rule. That asymmetry is what made the missing mask check worth
# more than an ordinary input-validation slip.
_MIN_PREFIX_V4 = 8
_MIN_PREFIX_V6 = 32


def _fwc_address_ok(text: str) -> bool:
    """True if a rich-rule source address is a real address, narrow enough.

    ipaddress does the parsing so the mask is judged as a number rather than as
    text: 1.2.3.4/0 and 0.0.0.0/0 are the same network and are both refused,
    which reading the address portion alone could never tell.
    """
    try:
        # strict=False: "192.168.1.5/24" names a host inside a network rather
        # than the network itself, and firewalld accepts that spelling.
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    floor = _MIN_PREFIX_V4 if net.version == 4 else _MIN_PREFIX_V6
    return net.prefixlen >= floor


def _fwc_rule_ok(arg: str) -> bool:
    """Full validation of one rich-rule string: shape, then blast radius."""
    for rx in _FWC_RULE_RES:
        m = rx.match(arg)
        if not m:
            continue
        # Only the two source-address patterns capture a group; port and MAC
        # rules carry no address to size up.
        return _fwc_address_ok(m.group(1)) if m.groups() else True
    return False


# Zone names accepted after --zone. The full built-in set is allowed because
# this only says *which* zone a rule applies to, and the host's default zone
# could legitimately be any of them. What made "trusted" dangerous was
# --set-default-zone, which could switch the machine into it; with that flag
# gone, naming a zone here grants nothing beyond adding drop rules to it.
_FWC_SAFE_ZONES  = ("public", "home", "drop", "block", "internal", "work",
                    "trusted", "external", "dmz")
_SYSCTL_ALLOWED = {
    # Fingerprint normalisation. Every one of these only changes how this host
    # presents itself; none of them can open a port, grant access or weaken a
    # filter, which is why they are safe to expose on this socket.
    "net.ipv4.ip_default_ttl",
    "net.ipv6.conf.all.hop_limit",
    "net.ipv4.tcp_timestamps",
    # Retained so a GUI older than this daemon can still restore what it set.
    "net.ipv4.tcp_window_scaling",
}
# systemd units the helper may stop/start (hostname/mDNS hiding).
#
# The .socket unit belongs here as much as the service does: it is configured
# to start the responder again on the first client connection, and clients
# (CUPS, file managers, nss-mdns) connect without being asked. Allowing only
# the service meant the hostname-hiding toggle quietly undid itself.
_SVC_ALLOWED    = {"avahi-daemon", "avahi-daemon.socket"}
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
        # A block by hardware address is as much an attacker block as one by
        # IP — it is the variant that survives the attacker renewing a DHCP
        # lease — so removing it needs the same consent. Checking only for
        # "source address=" let any maze-group process lift MAC blocks silently.
        if "source address=" in rule or "source mac=" in rule:
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
    _CAPTURE["pushed"] += 1
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
        # IPv6 addresses are ours too. Omitting them meant our own v6 traffic
        # was pushed to the clients as somebody else's.
        for m in _re.finditer(r'inet6 ([0-9a-fA-F:]+)/', out):
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
#   udp dst port 53         — plaintext DNS *queries*, for leak/hijack
#                             detection. The one class of packet we want from
#                             this host rather than towards it: a query
#                             escaping the VPN tunnel is the leak, and it is
#                             ours. Only the question is captured — the answer
#                             adds nothing this does not already know, and
#                             admitting it would double the volume.
#   ip6 tcp without ACK     — the same scan detection over IPv6. BPF cannot
#                             use tcp[tcpflags] on v6 (the offset is only
#                             fixed when no extension headers are present), so
#                             the flag byte is read at its literal position:
#                             40 bytes of IPv6 header + 13 into the TCP header.
#   icmp6 type 128/134      — v6 ping sweeps, and Router Advertisements. A
#                             forged RA is the IPv6 MITM: it makes the
#                             attacker your default router, and unlike rogue
#                             DHCP it needs no lease and no race.
_SNIFF_BPF = (
    "arp"
    " or (icmp and (icmp[icmptype] = 8 or icmp[icmptype] = 13"
    " or icmp[icmptype] = 17))"
    " or (tcp and tcp[tcpflags] & tcp-ack = 0 and"
    " (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-push|tcp-urg) != 0"
    " or tcp[tcpflags] = 0))"
    " or (udp and (port 67 or port 68 or dst port 53))"
    " or (ip6 and tcp and ip6[53] & 0x10 = 0)"
    " or (icmp6 and (ip6[40] = 128 or ip6[40] = 134))"
)
# What the capture has actually done since the daemon started. This exists to
# answer one question the GUI cannot answer for itself: when a detector has
# received no packets, is the network quiet or is the capture dead? The two
# look identical from the client side and mean opposite things — "nobody is
# attacking you" versus "you would not know if they were" — so the counters
# are kept here, where the packets actually arrive, and read back on request.
_CAPTURE = {"packets": 0, "pushed": 0, "iface": "", "started": 0.0}


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


def _sniff_once(iface: str, limiter: "_PushLimiter", stop_after: int,
                should_stop=None) -> None:
    from scapy.all import ARP, DHCP, ICMP, IP, IPv6, TCP, UDP, sniff
    from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6EchoRequest

    own_ips: set[str] = _get_iface_ips(iface)
    own_ips_refreshed_at: float = time.monotonic()

    def handle(pkt):
        nonlocal own_ips, own_ips_refreshed_at
        _CAPTURE["packets"] += 1
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

        if pkt.haslayer(IPv6):
            _handle_v6(pkt, own_ips, limiter)
            return

        if not pkt.haslayer(IP):
            return
        src, dst = pkt[IP].src, pkt[IP].dst

        # DNS is handled before the own-address filter on purpose. Every other
        # packet here is something being done *to* this host, so traffic we
        # sent is noise; a plaintext DNS query is the opposite — the leak that
        # matters is the one leaving this machine, and it carries our address.
        if pkt.haslayer(UDP) and int(pkt[UDP].dport) == 53:
            # Only our own queries. In promiscuous mode we also see the
            # neighbours' DNS, which is neither our business nor our leak.
            if src in own_ips:
                if limiter.allow():
                    _push({"event": "dns", "src": src, "dst": dst,
                           "sport": int(pkt[UDP].sport), "dport": 53,
                           "outbound": True})
            return

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
          timeout=stop_after, stop_filter=should_stop)


def _handle_v6(pkt, own_ips: set, limiter: "_PushLimiter") -> None:
    """Push the IPv6 packets that mean something to a detector.

    Deliberately narrow, and in the same shape the IPv4 branch uses: the client
    side analyses addresses as opaque strings, so a v6 source flows through the
    scan detector and the dossier without any of them knowing the difference.
    """
    from scapy.all import IPv6, TCP
    from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6EchoRequest

    ip6 = pkt[IPv6]
    src, dst = str(ip6.src), str(ip6.dst)

    # A Router Advertisement is reported whoever sent it — including ourselves
    # in the pathological case — because the question it answers is "how many
    # routers claim this link", and an answer that hides one is useless.
    if pkt.haslayer(ICMPv6ND_RA):
        if limiter.allow():
            _push({"event": "ra", "src": src, "dst": dst,
                   "lifetime": int(getattr(pkt[ICMPv6ND_RA], "routerlifetime", 0)),
                   "prf": int(getattr(pkt[ICMPv6ND_RA], "prf", 0))})
        return

    if src in own_ips:
        return

    if pkt.haslayer(TCP):
        if not limiter.allow():
            return
        tcp = pkt[TCP]
        _push({"event": "tcp", "src": src, "dst": dst,
               "sport": int(tcp.sport), "dport": int(tcp.dport),
               "flags": _tcp_flag_str(tcp.flags), "ttl": int(ip6.hlim),
               "win": int(tcp.window), "v6": True})
    elif pkt.haslayer(ICMPv6EchoRequest):
        if limiter.allow():
            _push({"event": "icmp", "src": src, "dst": dst,
                   "type": 8, "ttl": int(ip6.hlim), "v6": True})


# How long one capture slice runs before the socket is torn down and rebuilt.
#
# This used to be 60 seconds, which meant roughly 600 open/close cycles in a
# five-hour session — every one of them putting the interface in and out of
# promiscuous mode. On a wired NIC that is only waste. On a USB WiFi adapter it
# is a hazard: tearing a capture down and standing it back up is exactly the
# path where rt2x00usb and friends mishandle a device that vanishes mid-flight,
# and that is not an exotic setup here — an external adapter is the normal way
# to get monitor mode, so it is what much of this audience runs.
#
# Long slices do not cost responsiveness, because `stop_filter` below leaves the
# capture the moment the interface actually changes rather than waiting for the
# slice to end. The timeout is now only a backstop for a link that goes away on
# an interface so quiet that no packet arrives to notice it with.
_SLICE_SECONDS = 600


def _iface_change_detector(current: str):
    """A scapy stop_filter that ends the capture when the link moved.

    Called once per captured packet, so it must be cheap: the answer is cached
    for a second, which on a busy interface turns thousands of resolutions into
    one. Any error means "keep capturing" — losing the capture is worse than a
    late switch, and the slice timeout catches it either way.
    """
    state = {"at": 0.0, "changed": False}

    def stop(_pkt) -> bool:
        now = time.monotonic()
        if now - state["at"] < 1.0:
            return state["changed"]
        state["at"] = now
        try:
            resolved = _resolve_iface(current)
            state["changed"] = bool(resolved and resolved != current)
        except Exception:
            state["changed"] = False
        return state["changed"]

    return stop


def _sniff_thread(iface: str) -> None:
    """Capture forever, surviving link changes.

    The capture is bounded rather than one endless call so the interface can be
    re-resolved. Without that, a WiFi reconnect or a switch to Ethernet left the
    helper sniffing a dead interface and the GUI silently blind — the failure
    mode looked exactly like "no attacks today".

    What bounds it is a `stop_filter` that notices the change, with a long
    timeout behind it; see _SLICE_SECONDS for why not a short timeout alone.
    """
    limiter = _PushLimiter(_PUSH_RATE_LIMIT)
    current = iface
    backoff = 1.0
    _CAPTURE["started"] = time.monotonic()
    while True:
        _CAPTURE["iface"] = current
        try:
            _sniff_once(current, limiter, stop_after=_SLICE_SECONDS,
                        should_stop=_iface_change_detector(current))
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
    """Run a command without blocking the event loop, with a hard time limit.

    `subprocess.run` called straight from a coroutine blocks the *entire*
    helper — one slow command and no other client request, not even a ping,
    gets answered. And `firewall-cmd` is not reliably fast: with firewalld
    stopped it sits in D-Bus activation until that times out. Everything the
    helper shells out to goes through here.

    An asyncio subprocess, not `subprocess.run` in a worker thread. The thread
    version could not be cancelled: a hung child held its worker until its own
    timeout, enough of them exhausted the default executor (min(32, cpu+4)
    workers) and then no command ran at all; and on SIGTERM, asyncio.run()
    waited for those threads to finish, so `systemctl stop/restart` sat out its
    10 s stop timeout and SIGKILLed the helper. Here a timeout OR a cancellation
    kills the child and the coroutine returns at once — shutdown included.

    Every way of giving up is written to the journal. A silent failure here
    reached the GUI as a firewall that "is not installed".
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception as exc:
        print(f"maze-helper: could not start {' '.join(args)}: {exc}",
              file=sys.stderr, flush=True)
        return _Completed(stderr=str(exc))
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        _kill_child(proc)
        await _reap(proc)
        print(f"maze-helper: timed out after {timeout}s: {' '.join(args)}",
              file=sys.stderr, flush=True)
        return _Completed(stderr=f"timed out after {timeout}s")
    except asyncio.CancelledError:
        # The request was abandoned (client gone, helper stopping): the child
        # must not outlive it.
        _kill_child(proc)
        raise
    return _Completed(returncode=proc.returncode,
                      stdout=out.decode(errors="replace"),
                      stderr=err.decode(errors="replace"))


def _kill_child(proc) -> None:
    try:
        proc.kill()
    except ProcessLookupError:
        pass


async def _reap(proc) -> None:
    """Collect a killed child so it does not linger as a zombie."""
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except (asyncio.TimeoutError, TimeoutError):
        pass


def _fw_unit_installed() -> bool:
    return any(Path(d, f"{_FW_UNIT}.service").exists()
               for d in ("/etc/systemd/system", "/usr/lib/systemd/system"))


async def _firewalld_active() -> bool:
    """Cheap, D-Bus-free check that firewalld is up.

    Guards every firewall-cmd call: asking a stopped firewalld anything is not
    an error worth waiting on, it is a question with a known answer.
    """
    r = await _run(["systemctl", "is-active", _FW_UNIT], timeout=5.0)
    return r.stdout.strip() == "active"


# Read-side cache for the firewall queries. Every one of them is one or more
# `firewall-cmd` processes — a Python interpreter start plus a D-Bus round trip
# that firewalld and polkit both have to service — and several GUI widgets ask
# on their own timers. Measured on a laptop with the window open: ~1.2
# firewall-cmd spawns per second, ~40% of a core across helper + firewalld +
# polkit, and a CPU that never cooled below 50 °C. Answers a few seconds old
# are perfectly good for a status widget; anything that CHANGES the firewall
# (fw_cmd, fw_service) drops the cache so the next read is fresh.
_FW_CACHE_TTL = 5.0
_fw_cache: dict[str, tuple[float, dict]] = {}


def _fw_cached(key: str) -> dict | None:
    hit = _fw_cache.get(key)
    if hit and time.monotonic() - hit[0] < _FW_CACHE_TTL:
        return dict(hit[1])
    return None


def _fw_remember(key: str, resp: dict) -> None:
    _fw_cache[key] = (time.monotonic(), dict(resp))


def _fw_forget() -> None:
    _fw_cache.clear()


async def _dispatch(req: dict, writer: asyncio.StreamWriter) -> dict:
    """Execute one request and return its response envelope."""
    cmd    = req.get("cmd", "")
    req_id = req.get("id", 0)
    resp: dict = {"id": req_id, "ok": False}

    if cmd == "ping":
        resp["ok"] = True

    elif cmd == "fw_list_all":
        cached = _fw_cached("list_all")
        if cached is not None:
            resp.update(cached)
        elif not await _firewalld_active():
            resp.update(ok=True, data="", err="firewalld is not running")
        else:
            r = await _run(["firewall-cmd", "--list-all"])
            resp.update(ok=(r.returncode == 0 or r.returncode == 252),
                        data=r.stdout)
            _fw_remember("list_all", {k: resp[k] for k in ("ok", "data")})

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
                if _fwc_rule_ok(a):
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
                    _fw_forget()

    elif cmd == "fw_list" and _fw_cached("list") is not None:
        resp.update(_fw_cached("list"))

    elif cmd == "fw_list":
        import re as _re
        data = {"ips": [], "ports_tcp": [], "ports_udp": [], "macs": []}
        r = (await _run(["firewall-cmd", "--list-rich-rules"])
             if await _firewalld_active() else _Completed())
        if r.returncode == 0 or r.returncode == 252:
            ip_re = _re.compile(r'source address="?([^"\s]+)"?')
            mac_re = _re.compile(r'source mac="?((?:[0-9a-fA-F]{2}:){5}'
                                 r'[0-9a-fA-F]{2})"?')
            port_re = _re.compile(r'port port="?(\d+)"? protocol="?(tcp|udp)"?')
            for line in r.stdout.splitlines():
                m = ip_re.search(line)
                if m:
                    data["ips"].append(m.group(1))
                    continue
                m = mac_re.search(line)
                if m:
                    data["macs"].append(m.group(1).lower())
                    continue
                m = port_re.search(line)
                if m and int(m.group(1)) not in data[f"ports_{m.group(2)}"]:
                    data[f"ports_{m.group(2)}"].append(int(m.group(1)))
        resp.update(ok=True, data=data)
        _fw_remember("list", {"ok": True, "data": data})

    elif cmd == "fw_state" and _fw_cached("state") is not None:
        resp.update(_fw_cached("state"))

    elif cmd == "fw_state":
        # One round-trip snapshot of everything the UI needs to render
        # an honest firewall widget. Reading these separately from the
        # GUI raced against itself and produced buttons whose label and
        # behaviour disagreed.
        state = {"installed": False, "running": False, "enabled": False,
                 "zone": "", "target": "", "panic": False}
        try:
            # "Installed" from the unit file on disk, not from the probe below:
            # a probe that timed out or failed to start used to make an
            # installed, running firewalld read as "not installed" — the GUI's
            # "Unavailable" — and that wrong answer was then cached.
            state["installed"] = _fw_unit_installed()
            r = await _run(["systemctl", "is-active", _FW_UNIT], timeout=5.0)
            if not r.stdout.strip():
                # systemctl always names a state (active, inactive, failed,
                # ...); nothing at all means the question was never answered.
                raise RuntimeError("could not read the firewalld state: "
                                   + (r.stderr.strip() or f"exit {r.returncode}"))
            state["running"] = r.stdout.strip() == "active"
            r = await _run(["systemctl", "is-enabled", _FW_UNIT], timeout=5.0)
            state["enabled"] = r.stdout.strip() == "enabled"
            if state["running"]:
                # `--list-all` describes the default zone and names it on its
                # first line ("public (default, active)"), so a separate
                # --get-default-zone process is one interpreter start wasted.
                r = await _run(["firewall-cmd", "--list-all"])
                lines = r.stdout.splitlines()
                if lines:
                    state["zone"] = lines[0].strip().split()[0] if lines[0].strip() else ""
                for line in lines:
                    s = line.strip().lower()
                    if s.startswith("target:"):
                        state["target"] = s.split(":", 1)[1].strip()
                        break
                r = await _run(["firewall-cmd", "--query-panic"])
                state["panic"] = r.stdout.strip() == "yes"
        except Exception as e:
            resp["err"] = str(e)
        # A half-read state is not an answer: say so (ok=False) and cache
        # nothing, so the very next poll asks again instead of the GUI showing
        # a guess until the cache expires.
        resp.update(ok="err" not in resp, data=state)
        if "err" not in resp:
            _fw_remember("state", {"ok": True, "data": state})

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
                _fw_forget()
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

    elif cmd == "capture_stats":
        stats = dict(_CAPTURE)
        stats["uptime_s"] = (round(time.monotonic() - stats["started"], 1)
                             if stats["started"] else 0.0)
        stats.pop("started", None)
        resp.update(ok=True, data=stats)

    elif cmd == "sysctl_get":
        key = req.get("key", "")
        if key not in _SYSCTL_ALLOWED:
            resp["err"] = "disallowed sysctl key"
        else:
            r = await _run(["sysctl", "-n", key], timeout=5.0)
            resp.update(ok=r.returncode == 0, data=r.stdout.strip(),
                        err=r.stderr.strip())

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
    # The semaphore caps how many requests RUN at once, not how many are
    # created. A client that pipelines lines faster than they are served could
    # sit thousands of tasks in this set waiting their turn — bounded only by
    # how fast it can write. Past this many outstanding, stop reading instead:
    # the socket's own buffer then applies the back-pressure, which is where it
    # belongs. Far above anything the GUI does on a timer.
    _MAX_PENDING = 64

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
        while True:
            # readline(), not `async for`: iterating the reader raises
            # ValueError when a line runs past asyncio's 64 KB limit, and that
            # is not one of the exceptions caught below — it escaped as an
            # unretrieved task exception instead of closing the connection.
            # A request that long is malformed by definition; every command
            # this helper takes is a short JSON object.
            try:
                raw = await reader.readline()
            except ValueError:
                _audit(writer, "closing connection: request line too long")
                break
            if not raw:
                break
            line = raw.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            while len(pending) >= _MAX_PENDING:
                # Wait for room rather than queueing without limit.
                await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
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

    # Stop on SIGTERM by waking this coroutine, not with loop.stop(): under
    # asyncio.run() stopping the loop while the main task is still pending
    # raises "Event loop stopped before Future completed", which systemd then
    # records as status=1/FAILURE on every single shutdown. start_unix_server
    # is already serving; leaving the `async with` closes the socket.
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        _loop.add_signal_handler(sig, stop.set)

    async with server:
        await stop.wait()
        # Hang up on every client before leaving `async with`: since Python
        # 3.12 Server.wait_closed() waits for all connections to end on their
        # own, and the GUI never disconnects. Every `systemctl stop/restart`
        # with a Maze Guard window open sat out the stop timeout and ended in
        # SIGKILL ("State 'stop-sigterm' timed out"). Closing a client ends its
        # _handle loop, which cancels its in-flight requests and, through
        # _run, kills their child processes.
        for w in list(_clients):
            w.close()


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
