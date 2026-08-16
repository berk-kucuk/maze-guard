"""
Self-check: prove every feature is actually working on this machine.

Run with `maze-guard --doctor`. Each check exercises the real thing — the
helper socket, firewalld, the capture filter, the polkit action, the resolvers
— rather than reporting that a module was imported. A feature that cannot work
here says so, and says what to do about it, because the failure mode this
guards against is a security tool that looks healthy while protecting nothing.
"""
import asyncio
import os
import shutil
import subprocess
from pathlib import Path

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"

_COLOURS = {OK: "\033[92m", WARN: "\033[93m", FAIL: "\033[91m", SKIP: "\033[90m"}
_MARKS = {OK: "PASS", WARN: "WARN", FAIL: "FAIL", SKIP: "SKIP"}
_RESET = "\033[0m"


class Report:
    def __init__(self):
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, section: str, name: str, status: str, detail: str = "") -> None:
        self.rows.append((section, name, status, detail))

    def count(self, status: str) -> int:
        return sum(1 for r in self.rows if r[2] == status)

    def print(self) -> None:
        colour = os.isatty(1)
        current = None
        for section, name, status, detail in self.rows:
            if section != current:
                current = section
                print(f"\n\033[1m{section}\033[0m" if colour else f"\n{section}")
            mark = _MARKS[status]
            if colour:
                mark = f"{_COLOURS[status]}{mark}{_RESET}"
            print(f"  [{mark}] {name}" + (f"\n         {detail}" if detail else ""))
        print(f"\n{self.count(OK)} passed, {self.count(WARN)} warnings, "
              f"{self.count(FAIL)} failed, {self.count(SKIP)} skipped\n")


# ── environment ──────────────────────────────────────────────────────────────

_TOOLS = [
    ("firewall-cmd", FAIL, "firewalld — required for every blocking feature"),
    ("systemctl",    FAIL, "systemd — required to control the firewall service"),
    ("ip",           FAIL, "iproute2 — required for interface and neighbour data"),
    ("pkcheck",      FAIL, "polkit — required to authorise turning protections off"),
    ("iwgetid",      WARN, "wireless_tools — without it, rogue-AP detection is blind"),
    ("ss",           WARN, "iproute2 ss — used for the open-ports table"),
    ("ping",         WARN, "iputils — used for the OS/latency hint during recon"),
]


def _check_tools(report: Report) -> None:
    for tool, severity, why in _TOOLS:
        if shutil.which(tool):
            report.add("Environment", tool, OK)
        else:
            report.add("Environment", tool, severity, f"not found — {why}")


def _check_python_deps(report: Report) -> None:
    for mod, why in (("scapy", "packet capture"), ("PyQt6", "the interface"),
                     ("httpx", "DoH validation"), ("qasync", "the event loop"),
                     ("cryptography", "TLS certificate checks")):
        try:
            __import__(mod)
            report.add("Environment", f"python: {mod}", OK)
        except Exception as exc:
            report.add("Environment", f"python: {mod}", FAIL,
                       f"{why} needs it — {exc}")


def _check_capture_filter(report: Report) -> None:
    """The BPF program is what decides which attacks are visible at all."""
    try:
        from scapy.arch.common import compile_filter
        from maze.helper import _SNIFF_BPF
        prog = compile_filter(_SNIFF_BPF, linktype=1)
        report.add("Detection", "capture filter compiles", OK,
                   f"{prog.bf_len} instructions")
    except Exception as exc:
        report.add("Detection", "capture filter compiles", FAIL, str(exc))


# ── privileged helper ────────────────────────────────────────────────────────

async def _check_helper(report: Report) -> object | None:
    from maze.helper_client import HelperClient, _SOCK_PATH

    if not Path(_SOCK_PATH).exists():
        report.add("Privileged helper", "socket present", FAIL,
                   f"{_SOCK_PATH} missing — start it with: "
                   f"sudo systemctl start maze-guard.service")
        return None
    report.add("Privileged helper", "socket present", OK, _SOCK_PATH)

    client = HelperClient()
    if not await client.connect():
        report.add("Privileged helper", "connect", FAIL,
                   "permission denied — are you in the 'maze' group? "
                   "(sudo usermod -aG maze $USER, then log out and back in)")
        return None

    if not await asyncio.wait_for(client.ping(), timeout=10):
        report.add("Privileged helper", "responds to ping", FAIL,
                   "connected but not answering — check: "
                   "journalctl -u maze-guard.service -e")
        return client
    report.add("Privileged helper", "responds to ping", OK)

    # A daemon older than the GUI answers the old commands and silently
    # ignores the new ones, which is the hardest failure to spot by eye.
    state = await client.fw_state()
    if state:
        report.add("Privileged helper", "up to date", OK,
                   "supports fw_state / fw_service")
    else:
        report.add("Privileged helper", "up to date", FAIL,
                   "the running daemon predates this GUI — restart it: "
                   "sudo systemctl restart maze-guard.service")
    return client


async def _check_firewall(report: Report, client) -> None:
    if client is None:
        report.add("Firewall", "state", SKIP, "no privileged helper")
        return
    from maze.protection.firewall import FirewallManager

    fw = FirewallManager()
    await fw.start(None, helper=client)
    state = fw.state
    if not state.installed:
        report.add("Firewall", "firewalld installed", FAIL,
                   "install firewalld — blocking features cannot work without it")
        return
    report.add("Firewall", "firewalld installed", OK)
    report.add("Firewall", "running", OK if state.running else FAIL,
               f"zone={state.zone or '?'}" if state.running
               else "stopped — start it from the Protection tab")
    if state.running:
        report.add("Firewall", "inbound shield",
                   OK if state.incoming_blocked else WARN,
                   "unsolicited inbound is dropped" if state.incoming_blocked
                   else "not blocking inbound — turn it on in the Protection tab")
        rules = state.rules or {}
        n = (len(rules.get("ips", [])) + len(rules.get("ports_tcp", []))
             + len(rules.get("ports_udp", [])))
        report.add("Firewall", "rule channel", OK, f"{n} Maze Guard rules active")
    if state.panic:
        report.add("Firewall", "panic mode", WARN,
                   "firewalld is in panic mode — ALL traffic is dropped")


def _check_polkit(report: Report) -> None:
    policy = Path("/usr/share/polkit-1/actions/org.mazeguard.policy")
    if not policy.exists():
        report.add("Authorisation", "polkit action installed", FAIL,
                   "org.mazeguard.policy missing — protections cannot be "
                   "turned off from the GUI. Reinstall the package.")
        return
    report.add("Authorisation", "polkit action installed", OK, str(policy))
    if shutil.which("pkaction"):
        try:
            r = subprocess.run(["pkaction", "--action-id",
                                "org.mazeguard.disable-protection"],
                               capture_output=True, text=True, timeout=5)
            report.add("Authorisation", "action registered",
                       OK if r.returncode == 0 else FAIL,
                       "" if r.returncode == 0 else "polkit has not picked it up")
        except Exception as exc:
            report.add("Authorisation", "action registered", WARN, str(exc))
    agent = subprocess.run(["pgrep", "-f", "polkit.*agent"],
                           capture_output=True, text=True)
    report.add("Authorisation", "desktop agent running",
               OK if agent.returncode == 0 else WARN,
               "" if agent.returncode == 0 else
               "no polkit agent — the consent prompt cannot be shown in this session")


# ── network features ─────────────────────────────────────────────────────────

def _check_interface(report: Report, cfg) -> None:
    from maze.utils.network_info import (get_active_physical_interface,
                                         get_interface_info)
    iface = get_active_physical_interface()
    if iface == "—":
        report.add("Network", "active interface", FAIL, "no interface is up")
        return
    info = get_interface_info(iface)
    report.add("Network", "active interface", OK,
               f"{iface}  ip={info.ip}  gw={info.gateway}"
               + (f"  ssid={info.ssid}" if info.ssid else ""))
    if cfg.interface != iface:
        report.add("Network", "configured interface", WARN,
                   f"config says '{cfg.interface}' but '{iface}' is the live one")
    else:
        report.add("Network", "configured interface", OK, cfg.interface)
    if info.gateway == "—":
        report.add("Network", "default gateway", WARN,
                   "no default route — MITM detection has nothing to anchor to")
    else:
        report.add("Network", "default gateway", OK, info.gateway)
    if info.vpn_ifaces:
        report.add("Network", "VPN", OK, ", ".join(info.vpn_ifaces))


async def _check_resolvers(report: Report) -> None:
    from maze.detection.dns_validator import DNSValidator, DOH_RESOLVERS
    validator = DNSValidator()
    reachable = 0
    for name, url in DOH_RESOLVERS.items():
        try:
            got = await asyncio.wait_for(
                validator._doh_resolve(url, "one.one.one.one"), timeout=8)
            if got:
                reachable += 1
                report.add("DNS", f"DoH: {name}", OK, ", ".join(sorted(got)[:2]))
            else:
                report.add("DNS", f"DoH: {name}", WARN, "empty answer")
        except Exception as exc:
            report.add("DNS", f"DoH: {name}", WARN, f"unreachable — {exc}")
    if reachable < 2:
        report.add("DNS", "poisoning detection", FAIL,
                   "fewer than two DoH resolvers reachable — there is no "
                   "trustworthy baseline to compare the local resolver against")
    else:
        report.add("DNS", "poisoning detection", OK,
                   f"{reachable} independent resolvers agree to compare against")

    from maze.protection.dns_leak import _get_configured_dns_servers
    servers = _get_configured_dns_servers()
    report.add("DNS", "configured resolvers", OK if servers else WARN,
               ", ".join(sorted(servers)) if servers else "none found in resolv.conf")


async def _check_tls(report: Report) -> None:
    from maze.detection.tls_monitor import TLSMonitor, _CANARY_HOSTS
    monitor = TLSMonitor()
    for host in _CANARY_HOSTS:
        try:
            digest = await asyncio.wait_for(
                asyncio.to_thread(monitor._get_spki_hash, host, 443), timeout=10)
            report.add("TLS", f"canary: {host}", OK if digest else WARN,
                       f"spki={digest[:16]}…" if digest
                       else "no certificate — offline, or 443 is blocked")
        except Exception as exc:
            report.add("TLS", f"canary: {host}", WARN, str(exc))


async def _check_recon(report: Report, cfg) -> None:
    from maze.utils.network_info import get_interface_info
    from maze.utils.recon import recon_ip, format_recon
    gw = get_interface_info(cfg.interface).gateway
    if gw == "—":
        report.add("Reconnaissance", "probe", SKIP, "no gateway to probe")
        return
    try:
        result = await asyncio.wait_for(recon_ip(gw, port_timeout=1.0), timeout=40)
        report.add("Reconnaissance", "probe the gateway", OK, format_recon(result))
    except Exception as exc:
        report.add("Reconnaissance", "probe the gateway", FAIL, str(exc))


async def _check_modules(report: Report, cfg, client) -> None:
    """Start every module, then stop it, and report which ones refuse."""
    from maze.core.engine import MazeEngine
    engine = MazeEngine(cfg, helper=client)
    for key in sorted(engine._modules):
        module = engine._modules[key]
        try:
            await engine._start_module(key)
            if key in engine._active:
                report.add("Modules", key, OK)
            else:
                report.add("Modules", key, FAIL, "start() did not take effect")
        except Exception as exc:
            report.add("Modules", key, FAIL, str(exc))
        finally:
            try:
                await engine._stop_module(key)
            except Exception:
                pass
        del module


def _check_storage(report: Report) -> None:
    from maze.core.incident import DATA_DIR
    from maze.utils.config import CONFIG_PATH
    for label, path in (("config", CONFIG_PATH.parent),
                        ("incident records", DATA_DIR)):
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".maze-doctor-probe"
            probe.write_text("ok")
            probe.unlink()
            report.add("Storage", label, OK, str(path))
        except Exception as exc:
            report.add("Storage", label, FAIL, f"{path}: {exc}")


def _check_translations(report: Report) -> None:
    from maze.gui.i18n import STRINGS
    missing = set(STRINGS["en"]) ^ set(STRINGS["tr"])
    report.add("Interface", "translations", OK if not missing else WARN,
               f"{len(STRINGS['en'])} keys, English and Turkish in step"
               if not missing else f"keys out of step: {sorted(missing)[:5]}")


# ── entry point ──────────────────────────────────────────────────────────────

async def _run(report: Report) -> None:
    from maze.utils.config import load_config
    cfg = load_config()

    _check_tools(report)
    _check_python_deps(report)
    _check_capture_filter(report)
    _check_storage(report)
    _check_translations(report)
    _check_interface(report, cfg)
    _check_polkit(report)

    client = await _check_helper(report)
    try:
        await _check_firewall(report, client)
        await _check_modules(report, cfg, client)
        await _check_resolvers(report)
        await _check_tls(report)
        await _check_recon(report, cfg)
    finally:
        if client is not None:
            await client.close()


def main() -> int:
    report = Report()
    print("Maze Guard — self-check")
    try:
        asyncio.run(_run(report))
    except KeyboardInterrupt:
        return 130
    report.print()
    return 1 if report.count(FAIL) else 0
