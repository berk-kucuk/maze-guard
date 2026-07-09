import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InterfaceInfo:
    name: str
    ip: str = "—"
    mac: str = "—"
    status: str = "down"
    gateway: str = "—"
    ssid: str = ""
    vpn_ifaces: list = field(default_factory=list)


@dataclass
class PortInfo:
    port: int
    protocol: str
    address: str
    process: str = ""


@dataclass
class FirewallStatus:
    active: bool = False
    maze_profile: str = ""
    rule_lines: list = field(default_factory=list)
    rules_raw: str = ""


# Interface name prefixes to exclude from "physical" detection
_VPN_PREFIXES     = ("tun", "wg", "ppp", "pvpn", "nordlynx", "proton", "vpn")
_VIRTUAL_PREFIXES = ("lo", "vmnet", "docker", "virbr", "veth", "br-", "dummy",
                     "bond", "team", "macvlan")


def _is_vpn(name: str) -> bool:
    return any(name.startswith(p) for p in _VPN_PREFIXES)


def _is_virtual(name: str) -> bool:
    return any(name.startswith(p) for p in _VIRTUAL_PREFIXES)


def _operstate(iface_path: Path) -> str:
    try:
        return (iface_path / "operstate").read_text().strip()
    except Exception:
        return "unknown"


def get_active_physical_interface() -> str:
    """Return the name of the best active physical interface (Ethernet preferred over WiFi)."""
    best_name: str | None = None
    best_is_wifi = True

    for iface_path in Path("/sys/class/net").iterdir():
        name = iface_path.name
        if _is_virtual(name) or _is_vpn(name):
            continue
        state = _operstate(iface_path)
        if state not in ("up", "unknown"):
            continue
        is_wifi = (iface_path / "wireless").exists()
        if best_name is None or (best_is_wifi and not is_wifi):
            best_name = name
            best_is_wifi = is_wifi

    return best_name or "—"


def get_active_vpn_interfaces() -> list[str]:
    """Return names of currently active VPN interfaces."""
    vpns = []
    for iface_path in Path("/sys/class/net").iterdir():
        name = iface_path.name
        if _is_vpn(name) and _operstate(iface_path) in ("up", "unknown"):
            vpns.append(name)
    return sorted(vpns)


def current_network_id(iface: str) -> str:
    """A stable identifier for the network currently attached to `iface`.

    WiFi networks are identified by SSID; wired networks by the default
    gateway's MAC address. Returns "" if nothing can be determined (link down).
    Used by the auto-profile watcher to tell trusted networks apart.
    """
    # WiFi: SSID is the natural identity.
    if (Path("/sys/class/net") / iface / "wireless").exists():
        try:
            ssid = subprocess.check_output(
                ["iwgetid", iface, "--raw"], text=True,
                timeout=2, stderr=subprocess.DEVNULL,
            ).strip()
            if ssid:
                return f"wifi:{ssid}"
        except Exception:
            pass
    # Wired (or SSID unavailable): use the gateway MAC.
    try:
        route = subprocess.check_output(
            ["ip", "route", "show", "default", "dev", iface],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        )
        m = re.search(r"default via (\S+)", route)
        if m:
            gw = m.group(1)
            neigh = subprocess.check_output(
                ["ip", "neigh", "show", gw], text=True,
                timeout=2, stderr=subprocess.DEVNULL,
            )
            mac = re.search(r"lladdr\s+([0-9a-f:]{17})", neigh)
            if mac:
                return f"gw:{mac.group(1)}"
    except Exception:
        pass
    return ""


def get_interface_info(iface: str) -> InterfaceInfo:
    info = InterfaceInfo(name=iface)
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            s = line.strip()
            if "state UP" in line:
                info.status = "up"
            if "link/ether" in s:
                info.mac = s.split()[1]
            if s.startswith("inet ") and "inet6" not in s:
                info.ip = s.split()[1].split("/")[0]
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        )
        # Use the gateway for the physical interface (skip VPN routes)
        for line in out.splitlines():
            if "default via" not in line:
                continue
            parts = line.split()
            try:
                dev = parts[parts.index("dev") + 1]
            except (ValueError, IndexError):
                continue
            if not _is_vpn(dev):
                info.gateway = parts[2]
                break
    except Exception:
        pass

    try:
        ssid = subprocess.check_output(
            ["iwgetid", iface, "--raw"],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        ).strip()
        info.ssid = ssid
    except Exception:
        pass

    info.vpn_ifaces = get_active_vpn_interfaces()
    return info


def get_open_ports() -> list[PortInfo]:
    seen: dict[int, PortInfo] = {}
    try:
        out = subprocess.check_output(
            ["ss", "-tlnp"], text=True, timeout=3, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            addr = parts[3]
            if ":" not in addr:
                continue
            port_str = addr.rsplit(":", 1)[-1]
            try:
                port_num = int(port_str)
            except ValueError:
                continue
            process = ""
            for part in parts[4:]:
                m = re.search(r'"([^"]+)"', part)
                if m:
                    process = m.group(1)
                    break
            # Prefer IPv4 entry; skip duplicates (dedup IPv4/IPv6)
            if port_num not in seen or (
                not addr.startswith("[") and seen[port_num].address.startswith("[")
            ):
                seen[port_num] = PortInfo(port=port_num, protocol="TCP",
                                          address=addr, process=process)
    except Exception:
        pass
    return sorted(seen.values(), key=lambda p: p.port)


def parse_firewall_output(raw: str) -> FirewallStatus:
    """Parse raw `nft list ruleset` output into a FirewallStatus."""
    if not raw.strip():
        return FirewallStatus()
    profile = ""
    if "maze_paranoid" in raw:
        profile = "Paranoid"
    elif "maze_public" in raw:
        profile = "Public WiFi"
    rule_lines = [
        ln.strip() for ln in raw.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
        and any(kw in ln for kw in ("accept", "drop", "reject", "masquerade"))
    ]
    return FirewallStatus(active=True, maze_profile=profile,
                          rule_lines=rule_lines, rules_raw=raw)


def get_firewall_status() -> FirewallStatus:
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            text=True, timeout=3, capture_output=True,
        )
        if "not permitted" in result.stderr or "permission" in result.stderr.lower():
            return FirewallStatus(active=False, maze_profile="(needs root)", rules_raw="")
        raw = result.stdout
    except FileNotFoundError:
        return FirewallStatus(active=False, maze_profile="(nft not found)", rules_raw="")
    except Exception:
        return FirewallStatus()

    return parse_firewall_output(raw
    )
