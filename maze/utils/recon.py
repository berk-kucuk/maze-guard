"""
Reconnaissance against a source that has already attacked us.

Triggered automatically on DANGEROUS events, and on demand from the Threats
tab. The goal is a dossier good enough to act on: who is this host, what is it
running, what is it *for*. Gathers reverse DNS, MAC + vendor, NetBIOS and mDNS
names, open ports with service banners, TLS certificate identity, an OS guess,
round-trip latency, and a risk assessment of what all that adds up to.

Scope guard: the engine only ever calls this for on-link private addresses.
Source IPs come from packet headers and are trivially spoofed, so probing a
public address here would mean attacking an uninvolved third party on command.
"""
import asyncio
import re
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass, field

_LLADDR_RE = re.compile(r'lladdr\s+([0-9a-f:]{17})')
_TITLE_RE  = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)

# Probing is capped so a dossier never turns into a scan of its own: at most
# this many sockets open at once, and the whole port sweep is time-boxed.
_MAX_CONCURRENT_PROBES = 48
_SWEEP_BUDGET = 25.0

_COMMON_PORTS = [
    # Standard services
    20, 21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 135, 137, 139, 143,
    161, 389, 443, 445, 465, 514, 515, 587, 593, 636, 873, 993, 995,
    # Apple / macOS / printing
    548, 631, 3283, 5000, 5009, 7000,
    # Remote access / desktop
    1194, 3389, 5900, 5901, 5938, 6000,
    # IoT / embedded / industrial
    102, 502, 1883, 2375, 2376, 8883, 47808,
    # Databases and caches
    1433, 1521, 3306, 5432, 5984, 6379, 7474, 9042, 9200, 11211, 27017,
    # Web and app servers
    3000, 4200, 5173, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9090,
    # File sharing / sync
    2049, 6881, 8384, 9091,
    # Mobile
    5555, 62078,
    # Commonly associated with offensive tooling or backdoors
    1080, 1337, 4444, 4445, 5554, 6667, 9001, 9050, 12345, 31337,
]
_PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 79: "Finger", 80: "HTTP", 88: "Kerberos", 102: "S7/ICS",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 137: "NetBIOS-NS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 502: "Modbus", 514: "Syslog", 515: "LPD",
    548: "AFP", 587: "SMTP-sub", 593: "RPC-HTTP", 631: "IPP/CUPS",
    636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS proxy", 1194: "OpenVPN", 1337: "backdoor?",
    1433: "MSSQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS",
    2375: "Docker (plain)", 2376: "Docker (TLS)", 3000: "dev/HTTP",
    3283: "Apple Remote Desktop", 3306: "MySQL", 3389: "RDP",
    4200: "dev/HTTP", 4444: "Metasploit?", 4445: "Metasploit?",
    5000: "UPnP/HTTP", 5009: "AirPort admin", 5173: "dev/HTTP",
    5432: "PostgreSQL", 5554: "backdoor?", 5555: "ADB",
    5900: "VNC", 5901: "VNC", 5938: "TeamViewer", 5984: "CouchDB",
    6000: "X11", 6379: "Redis", 6667: "IRC (C2?)", 6881: "BitTorrent",
    7000: "AirPlay", 7474: "Neo4j", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8080: "HTTP-alt", 8081: "HTTP-alt", 8088: "HTTP-alt", 8384: "Syncthing",
    8443: "HTTPS-alt", 8883: "MQTT-TLS", 8888: "HTTP-alt", 9001: "Tor ORPort?",
    9042: "Cassandra", 9050: "Tor SOCKS", 9090: "HTTP-admin",
    9091: "Transmission", 9200: "Elasticsearch", 11211: "Memcached",
    12345: "NetBus?", 27017: "MongoDB", 31337: "Back Orifice?",
    47808: "BACnet", 62078: "iOS/lockdownd",
}

# Ports that say something about intent rather than function. Weight is the
# contribution to the risk score.
_RISK_PORTS: dict[int, tuple[int, str]] = {
    4444:  (30, "Metasploit default handler port"),
    4445:  (25, "Metasploit handler port"),
    5554:  (25, "known worm/backdoor port"),
    31337: (30, "Back Orifice / elite backdoor port"),
    12345: (25, "NetBus backdoor port"),
    1337:  (20, "commonly used backdoor port"),
    1080:  (15, "open SOCKS proxy — traffic laundering"),
    9050:  (10, "Tor SOCKS proxy running locally"),
    9001:  (10, "possible Tor relay"),
    6667:  (15, "IRC — historically used for botnet C2"),
    23:    (15, "Telnet — plaintext remote shell"),
    2375:  (25, "unauthenticated Docker API — full host takeover"),
    6379:  (20, "Redis — frequently exposed without auth"),
    11211: (15, "Memcached — amplification source"),
    5555:  (10, "Android debug bridge open"),
    6000:  (10, "X11 open to the network"),
}

# OUI prefix → vendor. Keys: uppercase hex, no colons, 6 chars (or 4 for
# vendors that use a 2-octet local prefix).
_OUI: dict[str, str] = {
    # Virtualisation
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware",
    "005056": "VMware", "080027": "VirtualBox",
    "0A0027": "VirtualBox (host-only)", "525400": "QEMU/KVM",
    "525401": "QEMU/KVM", "00155D": "Microsoft Hyper-V",
    "001600": "Parallels", "001C42": "Parallels", "0242": "Docker",
    # Single-board / embedded
    "DCA632": "Raspberry Pi", "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi", "DC2B61": "Raspberry Pi",
    "2CCF67": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    "18FE34": "Espressif (ESP8266/32)", "240AC4": "Espressif",
    "3C71BF": "Espressif", "A020A6": "Espressif",
    # Phones / laptops
    "000393": "Apple", "001451": "Apple", "0026BB": "Apple",
    "3C0754": "Apple", "A4C361": "Apple", "F0DBF8": "Apple",
    "8C8590": "Apple", "AC87A3": "Apple",
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google",
    "94EB2C": "Google", "D8C4E9": "Samsung", "3413A8": "Samsung",
    "0021D1": "Samsung", "F409D8": "Samsung",
    "00E04C": "Realtek", "001132": "Synology", "0011D8": "ASUSTek",
    "1C872C": "ASUSTek", "38D547": "ASUSTek",
    "00248C": "ASUSTek", "B06EBF": "ASUSTek",
    # Network gear
    "000C41": "Cisco/Linksys", "00184D": "Netgear", "A00460": "Netgear",
    "001E2A": "Netgear", "C03F0E": "Netgear", "0018E7": "Cameo/TP-Link",
    "F81A67": "TP-Link", "50C7BF": "TP-Link", "9C5322": "Compal",
    "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "802AA8": "Ubiquiti",
    "001DAA": "MikroTik", "4C5E0C": "MikroTik", "6C3B6B": "MikroTik",
    "00095B": "Netgear", "001CDF": "Belkin", "944452": "Belkin",
    "E894F6": "TP-Link", "1C61B4": "Huawei", "00E0FC": "Huawei",
    "D02DB3": "Huawei", "F8E71E": "Ruckus",
    "3C1E04": "D-Link", "1CBDB9": "D-Link", "0022B0": "D-Link",
    # Printers / IoT
    "3C2AF4": "Brother", "0080770": "Brother", "002128": "HP",
    "3CD92B": "HP", "94F128": "HP", "0017C8": "Kyocera",
    "B8278C": "Sonos", "5CAAFD": "Sonos", "D073D5": "LIFX",
    "18B430": "Nest", "6055F9": "Nest", "ECFABC": "Xiaomi",
    "7811DC": "Xiaomi", "64B473": "Xiaomi", "50EC50": "Amazon",
    "FCA667": "Amazon", "68370E": "Amazon",
}

# Locally-administered MAC bit — set by MAC randomisation. Worth flagging: a
# randomised MAC on a host that is scanning you is a deliberate choice.
_LOCAL_MAC_BIT = 0x02


@dataclass
class ReconResult:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: list[tuple[int, str]] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    os_hint: str = ""
    netbios_name: str = ""
    mdns_name: str = ""
    tls_info: dict = field(default_factory=dict)
    http_titles: dict[int, str] = field(default_factory=dict)
    latency_ms: float = 0.0
    randomized_mac: bool = False
    risk_score: int = 0
    findings: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.netbios_name or self.mdns_name or self.hostname

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostname": self.hostname, "mac": self.mac,
            "vendor": self.vendor, "open_ports": self.open_ports,
            "banners": {str(k): v for k, v in self.banners.items()},
            "os_hint": self.os_hint, "netbios_name": self.netbios_name,
            "mdns_name": self.mdns_name, "tls_info": self.tls_info,
            "http_titles": {str(k): v for k, v in self.http_titles.items()},
            "latency_ms": self.latency_ms,
            "randomized_mac": self.randomized_mac,
            "risk_score": self.risk_score, "findings": self.findings,
        }


async def recon_ip(ip: str, port_timeout: float = 1.5) -> ReconResult:
    result = ReconResult(ip=ip)

    hostname, ports, ping, mac, netbios, mdns = await asyncio.gather(
        _reverse_dns(ip),
        _scan_ports(ip, port_timeout),
        _ping(ip),
        _get_mac(ip),
        _netbios_query(ip),
        _mdns_query(ip),
        return_exceptions=True,
    )

    if isinstance(hostname, str):
        result.hostname = hostname
    if isinstance(ports, list):
        result.open_ports = ports
    if isinstance(mac, str) and mac:
        result.mac = mac
        result.vendor = _oui_lookup(mac)
        result.randomized_mac = _is_randomized(mac)
    if isinstance(netbios, str) and netbios:
        result.netbios_name = netbios
    if isinstance(mdns, str) and mdns:
        result.mdns_name = mdns

    ttl_hint = ""
    if isinstance(ping, tuple):
        ttl_hint, result.latency_ms = ping

    port_nums = {p for p, _ in result.open_ports}
    result.os_hint = _enrich_os(ttl_hint, port_nums)

    # Second pass: talk to whatever answered, to learn what it is.
    await _fingerprint_services(ip, result, port_nums)

    _assess_risk(result, port_nums)
    return result


# ── service fingerprinting ────────────────────────────────────────────────────

async def _fingerprint_services(ip: str, result: ReconResult,
                                port_nums: set[int]) -> None:
    """Grab banners, HTTP identity and TLS certificate details in parallel."""
    banner_ports = sorted(port_nums & {21, 22, 23, 25, 110, 143, 143, 587,
                                       6379, 11211, 6667})
    http_ports = sorted(port_nums & {80, 3000, 4200, 5173, 8000, 8008, 8080,
                                     8081, 8088, 8888, 9090})
    tls_ports = sorted(port_nums & {443, 8443, 465, 993, 995, 636, 8883})

    jobs = (
        [_banner_grab(ip, p, 2.0) for p in banner_ports]
        + [_http_probe(ip, p, 2.5) for p in http_ports]
        + [_tls_probe(ip, p, 3.0) for p in tls_ports[:2]]
    )
    if not jobs:
        return
    outcomes = await asyncio.gather(*jobs, return_exceptions=True)

    idx = 0
    for port in banner_ports:
        val = outcomes[idx]; idx += 1
        if isinstance(val, str) and val:
            result.banners[port] = val
    for port in http_ports:
        val = outcomes[idx]; idx += 1
        if isinstance(val, tuple):
            server, title = val
            if server:
                result.banners[port] = server
            if title:
                result.http_titles[port] = title
    for port in tls_ports[:2]:
        val = outcomes[idx]; idx += 1
        if isinstance(val, dict) and val:
            result.tls_info[str(port)] = val


async def _http_probe(ip: str, port: int, timeout: float) -> tuple[str, str]:
    """Return (server header, page title) — cheap identity for a web UI."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return "", ""
    try:
        writer.write(b"GET / HTTP/1.1\r\nHost: " + ip.encode()
                     + b"\r\nUser-Agent: Maze-Guard\r\nConnection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        text = data.decode(errors="replace")
        server = ""
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                server = line[7:].strip()[:80]
                break
            if not line.strip():
                break
        m = _TITLE_RE.search(text)
        title = re.sub(r'\s+', ' ', m.group(1)).strip()[:80] if m else ""
        return server, title
    except Exception:
        return "", ""
    finally:
        await _close(writer)


async def _tls_probe(ip: str, port: int, timeout: float) -> dict:
    """Pull the certificate a host presents.

    A self-signed cert with a throwaway CN on a machine that just scanned you
    is a different story from a printer with a vendor cert, so the identity is
    worth recording even though we never trust it.
    """
    def _fetch() -> dict:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                info = tls.getpeercert()  # empty dict when unverified
                version = tls.version() or ""
        out: dict = {"tls_version": version}
        if der:
            import hashlib
            out["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()[:32]
            out.update(_parse_cert_der(der))
        if info:
            out["subject"] = _flatten_name(info.get("subject", ()))
            out["issuer"] = _flatten_name(info.get("issuer", ()))
            out["not_after"] = info.get("notAfter", "")
        return out

    try:
        return await asyncio.wait_for(asyncio.to_thread(_fetch), timeout + 2)
    except Exception:
        return {}


def _parse_cert_der(der: bytes) -> dict:
    """Best-effort CN/issuer extraction without a certificate library.

    ssl.getpeercert() returns nothing useful when verification is off, and the
    hosts we point this at are exactly the ones with untrusted certs, so the
    common names are scraped out of the DER instead.
    """
    out: dict = {}
    try:
        # CN OID 2.5.4.3 encodes as 55 04 03, followed by a string tag.
        names: list[str] = []
        i = 0
        while True:
            i = der.find(b'\x55\x04\x03', i)
            if i < 0:
                break
            j = i + 3
            if j + 2 <= len(der) and der[j] in (0x0c, 0x13, 0x16, 0x1e):
                length = der[j + 1]
                value = der[j + 2:j + 2 + length]
                try:
                    names.append(value.decode("utf-8", errors="replace"))
                except Exception:
                    pass
            i = j
        if names:
            out["issuer_cn"] = names[0]
            out["subject_cn"] = names[-1]
            out["self_signed"] = names[0] == names[-1]
    except Exception:
        pass
    return out


def _flatten_name(rdn) -> str:
    parts = []
    for entry in rdn or ():
        for key, value in entry:
            if key in ("commonName", "organizationName"):
                parts.append(str(value))
    return ", ".join(parts)[:120]


# ── risk assessment ───────────────────────────────────────────────────────────

def _assess_risk(result: ReconResult, port_nums: set[int]) -> None:
    """Turn observations into a score and a list of plain-language findings."""
    score = 0
    findings: list[str] = []

    for port, (weight, why) in _RISK_PORTS.items():
        if port in port_nums:
            score += weight
            findings.append(f"port {port} open — {why}")

    if result.randomized_mac:
        score += 10
        findings.append("MAC address is randomised — the host is hiding its identity")

    if len(port_nums) >= 15:
        score += 10
        findings.append(f"{len(port_nums)} services exposed — unusually broad "
                        f"attack surface for a client device")

    for port, info in result.tls_info.items():
        if info.get("self_signed"):
            score += 5
            findings.append(f"self-signed certificate on port {port}"
                            + (f" (CN={info.get('subject_cn')})"
                               if info.get("subject_cn") else ""))

    for port, banner in result.banners.items():
        low = banner.lower()
        if "openssh" in low and re.search(r'openssh[_ ]([0-6])\.', low):
            score += 10
            findings.append(f"outdated SSH on port {port}: {banner}")
        if "kali" in low or "parrot" in low:
            score += 25
            findings.append(f"penetration-testing distribution identified: {banner}")

    if result.os_hint.startswith("Android") and 5555 in port_nums:
        findings.append("Android device with ADB exposed — remotely controllable")

    result.risk_score = min(100, score)
    result.findings = findings


# ── OS detection ──────────────────────────────────────────────────────────────

async def _ping(ip: str) -> tuple[str, float]:
    """Return (OS hint from TTL, round-trip time in ms)."""
    try:
        started = time.monotonic()
        r = await asyncio.to_thread(
            subprocess.run,
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        )
        rtt = (time.monotonic() - started) * 1000
        if r.returncode == 0:
            m = re.search(r"time=([\d.]+) ?ms", r.stdout)
            if m:
                rtt = float(m.group(1))
            m = re.search(r"ttl=(\d+)", r.stdout.lower())
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:
                    return "Linux / Unix", round(rtt, 2)
                if ttl <= 128:
                    return "Windows", round(rtt, 2)
                return "Network device", round(rtt, 2)
    except Exception:
        pass
    return "", 0.0


def _enrich_os(base: str, port_nums: set[int]) -> str:
    """Refine OS classification using discovered port profile.

    TTL=64 alone covers Linux, macOS, Android, iOS, FreeBSD — open ports
    let us narrow it down significantly.
    """
    if 5555 in port_nums:
        return "Android (ADB enabled)"
    if 62078 in port_nums:
        return "iOS"
    if 135 in port_nums or (445 in port_nums and 139 in port_nums):
        return "Windows"
    # AFP and Apple Remote Desktop are Apple-only. CUPS is not: it ships on
    # every Linux desktop, and treating it as an Apple signal labelled ordinary
    # Linux hosts (including this one) "macOS".
    if 3283 in port_nums or 548 in port_nums:
        return "macOS"
    if port_nums & {102, 502, 47808}:
        return "Industrial controller / ICS"
    if (80 in port_nums or 443 in port_nums or 8080 in port_nums) and \
       not port_nums & {22, 445, 135, 3389}:
        if base == "Network device" or (base == "Linux / Unix" and
           not port_nums & {22, 25, 110, 143, 5432, 3306}):
            return "Router / Embedded device"
    return base


# ── name resolution ───────────────────────────────────────────────────────────

async def _netbios_query(ip: str, timeout: float = 1.5) -> str:
    """Query NetBIOS Name Service (UDP 137) for the Windows machine name."""
    pkt = (
        b'\xab\xcd'          # Transaction ID
        b'\x00\x00'          # Flags: request
        b'\x00\x01'          # Questions: 1
        b'\x00\x00'          # Answer RRs
        b'\x00\x00'          # Authority RRs
        b'\x00\x00'          # Additional RRs
        b'\x20'              # Length of encoded name (32)
        + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # Encoded wildcard '*'
        + b'\x00'            # Root label
        b'\x00\x21'          # Type: NBSTAT
        b'\x00\x01'          # Class: IN
    )
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_send_netbios, ip, pkt), timeout=timeout)
    except Exception:
        return ""


def _send_netbios(ip: str, pkt: bytes) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(pkt, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) < 57:
            return ""
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name = data[offset:offset + 15].decode(errors="replace").strip()
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            # Type 0x0000 = workstation name (machine name)
            if flags & 0x8000 == 0 and name:
                return name
            offset += 18
    except Exception:
        pass
    return ""


async def _mdns_query(ip: str, timeout: float = 2.0) -> str:
    """Ask the host directly for its mDNS name (reverse PTR over unicast).

    Apple, Android and Linux devices answer this where NetBIOS gets nothing,
    and the answer is the name the owner actually chose ("berk-macbook"),
    which is far more identifying than an IP.
    """
    def _query() -> str:
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return ""
            qname = b""
            for label in list(reversed(octets)) + ["in-addr", "arpa"]:
                enc = label.encode()
                qname += bytes([len(enc)]) + enc
            qname += b"\x00"
            # QU (unicast-response) bit set in qclass so the host replies to us
            # directly rather than multicasting.
            pkt = (struct.pack(">HHHHHH", 0x4d5a, 0, 1, 0, 0, 0)
                   + qname + struct.pack(">HH", 12, 0x8001))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(pkt, (ip, 5353))
            data, _ = sock.recvfrom(2048)
            sock.close()
            return _parse_ptr_answer(data)
        except Exception:
            return ""

    try:
        return await asyncio.wait_for(asyncio.to_thread(_query), timeout + 1)
    except Exception:
        return ""


def _parse_ptr_answer(data: bytes) -> str:
    """Pull the first PTR target out of a DNS response."""
    try:
        if len(data) < 12:
            return ""
        qd, an = struct.unpack(">HH", data[4:8])
        if an < 1:
            return ""
        pos = 12
        for _ in range(qd):                       # skip the question section
            pos = _skip_name(data, pos) + 4
        for _ in range(an):
            pos = _skip_name(data, pos)
            rtype = struct.unpack(">H", data[pos:pos + 2])[0]
            rdlen = struct.unpack(">H", data[pos + 8:pos + 10])[0]
            rdata = pos + 10
            if rtype == 12:                       # PTR
                return _read_name(data, rdata).rstrip(".")
            pos = rdata + rdlen
    except Exception:
        pass
    return ""


def _skip_name(data: bytes, pos: int) -> int:
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:                 # compression pointer
            return pos + 2
        pos += length + 1
    return pos


def _read_name(data: bytes, pos: int, depth: int = 0) -> str:
    labels: list[str] = []
    while pos < len(data) and depth < 10:
        length = data[pos]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            labels.append(_read_name(data, ptr, depth + 1))
            break
        labels.append(data[pos + 1:pos + 1 + length].decode(errors="replace"))
        pos += length + 1
    return ".".join(l for l in labels if l)


async def _reverse_dns(ip: str) -> str:
    try:
        info = await asyncio.to_thread(lambda: socket.getnameinfo((ip, 0), 0))
        hostname = info[0]
        return hostname if hostname != ip else ""
    except Exception:
        return ""


# ── layer 2 ───────────────────────────────────────────────────────────────────

async def _get_mac(ip: str) -> str:
    try:
        out = await asyncio.to_thread(
            subprocess.check_output, ["ip", "neigh", "show", ip], text=True
        )
        m = _LLADDR_RE.search(out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _oui_lookup(mac: str) -> str:
    clean = mac.replace(":", "").upper()
    return _OUI.get(clean[:6]) or _OUI.get(clean[:4]) or ""


def _is_randomized(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & _LOCAL_MAC_BIT)
    except (ValueError, IndexError):
        return False


# ── port sweep ────────────────────────────────────────────────────────────────

async def _scan_ports(ip: str, timeout: float) -> list[tuple[int, str]]:
    sem = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)

    async def probe(port: int) -> bool:
        async with sem:
            return await _check_port(ip, port, timeout)

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*[probe(p) for p in _COMMON_PORTS],
                           return_exceptions=True),
            timeout=_SWEEP_BUDGET,
        )
    except asyncio.TimeoutError:
        return []
    return [
        (p, _PORT_NAMES.get(p, "?"))
        for p, r in zip(_COMMON_PORTS, results)
        if r is True
    ]


async def _check_port(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        await _close(writer)
        return True
    except Exception:
        return False


async def _banner_grab(ip: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except Exception:
        return ""
    try:
        if port in (6379, 11211):
            # Both answer a version query without authentication when exposed.
            writer.write(b"version\r\n" if port == 11211 else b"INFO server\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        text = data.decode(errors="replace")
        for line in text.splitlines():
            if line.strip():
                return line.strip()[:100]
        return ""
    except Exception:
        return ""
    finally:
        await _close(writer)


async def _close(writer) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


# ── formatter ─────────────────────────────────────────────────────────────────

def format_recon(result: ReconResult) -> str:
    parts = [f"Recon: {result.ip}"]
    if result.mac:
        mac_str = result.mac
        if result.vendor:
            mac_str += f" ({result.vendor})"
        if result.randomized_mac:
            mac_str += " [randomised]"
        parts.append(f"mac={mac_str}")
    if result.name:
        parts.append(f"hostname={result.name}")
    if result.os_hint:
        parts.append(f"os={result.os_hint}")
    if result.latency_ms:
        parts.append(f"rtt={result.latency_ms}ms")
    if result.open_ports:
        ports_str = ", ".join(f"{p}/{n}" for p, n in result.open_ports[:8])
        parts.append(f"open_ports=[{ports_str}]")
    if result.banners:
        banner_parts = [f"{p}:{b}" for p, b in list(result.banners.items())[:3]]
        parts.append(f"banners=[{'; '.join(banner_parts)}]")
    if result.risk_score:
        parts.append(f"risk={result.risk_score}/100")
    if result.findings:
        parts.append(f"findings=[{'; '.join(result.findings[:3])}]")
    return " | ".join(parts)
