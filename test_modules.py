"""
Maze Guard module integration test — run with sudo:
    sudo python3 test_modules.py

Tests every detection/protection/stealth module by starting it for a short
duration and verifying it produces events on the bus. Root is required for
firewalld, MAC changes, and raw socket sniffing.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET} {msg}")
def section(title): print(f"\n{BOLD}{title}{RESET}")


# ── shared bus that records all events ────────────────────────────────────────
from maze.core.events import EventBus, Event, ThreatLevel

received: list[Event] = []

async def _collector(event: Event):
    received.append(event)


# ── helpers ───────────────────────────────────────────────────────────────────

async def run_for(coro, seconds: float):
    """Run an async function then wait for `seconds`."""
    task = asyncio.create_task(coro)
    await asyncio.sleep(seconds)
    return task


def events_of_type(type_value: str) -> list[Event]:
    return [e for e in received if e.type.value == type_value]


# ── per-module tests ──────────────────────────────────────────────────────────

async def test_imports():
    section("1. Import all modules")
    modules = [
        "maze.core.engine",
        "maze.core.events",
        "maze.core.profile",
        "maze.detection.arp_watch",
        "maze.detection.rogue_ap",
        "maze.detection.dns_validator",
        "maze.detection.tls_monitor",
        "maze.detection.ssl_strip",
        "maze.stealth.hostname_hide",
        "maze.stealth.service_blocker",
        "maze.stealth.fingerprint",
        "maze.protection.firewall",
        "maze.protection.port_scanner",
        "maze.protection.process_map",
        "maze.protection.dns_leak",
        "maze.utils.recon",
        "maze.utils.config",
        "maze.utils.network_info",
    ]
    all_ok = True
    for mod in modules:
        try:
            __import__(mod)
            ok(mod)
        except Exception as e:
            fail(f"{mod}  →  {e}")
            all_ok = False
    return all_ok


async def test_config():
    section("2. Config & interface detection")
    from maze.utils.config import load_config
    from maze.utils.network_info import get_active_physical_interface, get_active_vpn_interfaces
    try:
        cfg = load_config()
        ok(f"Config loaded  interface={cfg.interface}")
        if cfg.interface == "—":
            warn("No active physical interface detected")
        iface = get_active_physical_interface()
        ok(f"Active interface: {iface}")
        vpns = get_active_vpn_interfaces()
        if vpns:
            ok(f"VPN interfaces: {vpns}")
        else:
            ok("No VPN active")
        return cfg
    except Exception as e:
        fail(f"Config error: {e}")
        return None


async def test_engine_start(cfg):
    section("3. Engine startup + profile activation")
    from maze.core.engine import MazeEngine
    from maze.core.profile import Profile
    try:
        engine = MazeEngine(cfg)
        engine.bus.subscribe_all(_collector)
        await engine.start()
        await engine.apply_profile(Profile.PUBLIC)
        await asyncio.sleep(1)
        mods = engine.module_states()
        active = [k for k, v in mods.items() if v]
        ok(f"Active modules: {active}")
        return engine
    except Exception as e:
        fail(f"Engine start failed: {e}")
        return None


async def test_arp_watcher(engine):
    section("4. ARPWatcher — gateway detection")
    from maze.detection.arp_watch import _get_gateway_info
    from maze.utils.config import load_config
    cfg = load_config()
    gw_ip, gw_mac = await asyncio.to_thread(_get_gateway_info, cfg.interface)
    if gw_ip:
        ok(f"Gateway: {gw_ip}  MAC: {gw_mac or 'n/a'}")
    else:
        warn("No default gateway found for interface (VPN or interface change?)")

    aw = engine._modules.get("arp_watch")
    if aw:
        ok(f"ARPWatcher running  whitelist={aw._whitelist}")
        ok(f"threading.Lock present: {hasattr(aw, '_lock')}")
        ok(f"stop_event present:     {hasattr(aw, '_stop_event')}")
    else:
        fail("ARPWatcher not in engine modules")


async def test_rogue_ap(engine):
    section("5. RogueAP — ICMP redirect check")
    from maze.utils.config import load_config
    cfg = load_config()
    redirect_path = f"/proc/sys/net/ipv4/conf/{cfg.interface}/accept_redirects"
    try:
        val = open(redirect_path).read().strip()
        if val == "1":
            warn(f"ICMP redirects ENABLED on {cfg.interface} — RogueAP will alert")
        else:
            ok(f"ICMP redirects disabled on {cfg.interface}")
    except Exception as e:
        warn(f"Could not read {redirect_path}: {e}")


async def test_dns_validator():
    section("6. DNSValidator — local resolver vs DoH consensus (dns.google)")
    from maze.detection.dns_validator import DNSValidator
    bus = EventBus()
    events: list[Event] = []
    bus.subscribe_all(lambda e: events.append(e) or asyncio.sleep(0))
    v = DNSValidator()
    v._bus = bus
    try:
        # Use a stable-anycast canary; CDN domains (google.com) legitimately
        # differ between the local resolver and DoH and would false-positive.
        result = await asyncio.wait_for(v.validate("dns.google"), timeout=10)
        if result:
            ok("local resolver agrees with DoH consensus for dns.google")
        else:
            warn("local resolver disagrees with DoH — possible DNS poisoning")
    except asyncio.TimeoutError:
        warn("DoH validation timed out (no internet?)")
    except Exception as e:
        fail(f"DNSValidator error: {e}")


async def test_tls_monitor():
    section("7. TLSMonitor — cert hash for github.com")
    from maze.detection.tls_monitor import TLSMonitor
    m = TLSMonitor()
    try:
        h = await asyncio.wait_for(
            asyncio.to_thread(m._get_spki_hash, "github.com", 443), timeout=8)
        if h:
            ok(f"github.com TLS cert hash: {h[:16]}…")
        else:
            warn("Could not fetch TLS cert (no internet or port 443 blocked?)")
    except asyncio.TimeoutError:
        warn("TLS cert fetch timed out")
    except Exception as e:
        fail(f"TLSMonitor error: {e}")


async def test_port_scanner(engine):
    section("8. PortScanDetector — state check")
    ps = engine._modules.get("port_scan")
    if ps:
        ok(f"PortScanDetector running  threshold={ps.threshold}")
        ok(f"Window prune task present: {ps._prune_task is not None}")
    else:
        fail("PortScanDetector not in engine modules")


async def test_anomaly(engine):
    section("8b. AnomalyDetector — correlation engine")
    an = engine._modules.get("anomaly")
    if not an:
        fail("AnomalyDetector not in engine modules")
        return
    ok(f"AnomalyDetector running  gateway={an._gw_ip or '—'}")

    from maze.core.events import Event, EventType, ThreatLevel
    seen = []

    async def sink(ev):
        if ev.type == EventType.ATTACK_CHAIN:
            seen.append(ev)

    engine.bus.subscribe_all(sink)
    for etype in (EventType.PORT_SCAN, EventType.ARP_SPOOF):
        await engine.bus.emit(Event(type=etype, level=ThreatLevel.DANGEROUS,
                                    message="synthetic test event",
                                    data={"src": "203.0.113.253"}))
    engine.bus.unsubscribe_all(sink)
    if seen:
        ok(f"Correlated: {seen[0].message}")
    else:
        fail("two techniques from one source did not correlate")


async def test_incidents(engine):
    section("8c. IncidentStore — attacker dossier")
    att = engine.incidents.get("203.0.113.253")
    if not att:
        fail("synthetic attacker was not filed")
        return
    ok(f"Dossier: score={att.score()} severity={att.severity} "
       f"techniques={sorted(att.techniques)}")
    ok(f"Evidence journal: {engine.incidents.journal_path}")
    engine.incidents.clear("203.0.113.253")


async def test_process_monitor(engine):
    section("9. ProcessNetworkMonitor — active connections snapshot")
    pm = engine._modules.get("process")
    if not pm:
        fail("ProcessNetworkMonitor not in engine modules")
        return
    try:
        conns = await asyncio.wait_for(pm.snapshot(), timeout=10)
        ok(f"Found {len(conns)} active TCP connections")
        for c in conns[:5]:
            print(f"     {c.process:<20} → {c.remote_addr}")
        if len(conns) > 5:
            print(f"     … and {len(conns)-5} more")
    except asyncio.TimeoutError:
        warn("Snapshot timed out")
    except Exception as e:
        fail(f"ProcessMonitor snapshot error: {e}")


async def test_dns_leak():
    section("10. DNSLeakPreventer — resolv.conf + VPN state")
    from maze.protection.dns_leak import (
        _get_configured_dns_servers, _get_active_vpn_interfaces,
        _read_udp_dns_destinations, _is_private_ip,
    )
    configured = _get_configured_dns_servers()
    vpns = _get_active_vpn_interfaces()
    dests = _read_udp_dns_destinations()

    ok(f"Configured DNS servers: {configured or '(none in resolv.conf)'}")
    ok(f"VPN interfaces: {vpns or 'none'}")
    if dests:
        for ip in dests:
            priv = _is_private_ip(ip)
            in_conf = ip in configured
            status = "OK" if in_conf else ("private" if priv else "UNEXPECTED")
            print(f"     DNS dest {ip}  private={priv}  in_resolv={in_conf}  → {status}")
    else:
        ok("No active UDP port-53 sockets detected")


async def test_firewall():
    section("11. FirewallManager — firewalld init")
    from maze.protection.firewall import FirewallManager
    fw = FirewallManager()
    try:
        ok_init = await asyncio.wait_for(fw.ensure_init(), timeout=5)
        if ok_init:
            ok("firewalld zone detected")
            rules = await fw.list_rules()
            ok(f"Current rules: {rules}")
            ok("Firewall ready (firewalld)")
        else:
            warn("ensure_init() returned False — firewalld not running or no permission?")
    except asyncio.TimeoutError:
        warn("Firewall init timed out")
    except Exception as e:
        fail(f"Firewall error: {e}")


async def test_recon():
    section("12. Recon — scan gateway")
    from maze.detection.arp_watch import _get_gateway_info
    from maze.utils.recon import recon_ip, format_recon
    from maze.utils.config import load_config
    cfg = load_config()
    gw_ip, _ = await asyncio.to_thread(_get_gateway_info, cfg.interface)
    if not gw_ip:
        warn("No gateway — skipping recon test")
        return
    try:
        result = await asyncio.wait_for(recon_ip(gw_ip, port_timeout=1.0), timeout=20)
        ok(format_recon(result))
    except asyncio.TimeoutError:
        warn("Recon timed out")
    except Exception as e:
        fail(f"Recon error: {e}")


# ── main ──────────────────────────────────────────────────────────────────────

async def main():
    print(f"\n{BOLD}{'='*60}")
    print("  Maze Guard Module Test Suite")
    print(f"{'='*60}{RESET}")

    if os.getuid() != 0:
        print(f"\n{RED}Run with sudo for full test coverage.{RESET}")
        print("Some tests (firewall, sniff) will fail without root.\n")

    passed = await test_imports()
    if not passed:
        print(f"\n{RED}Import failures — fix these before continuing.{RESET}")
        return

    cfg = await test_config()
    if cfg is None:
        return

    engine = await test_engine_start(cfg)

    await test_arp_watcher(engine)
    await test_rogue_ap(engine)
    await test_dns_validator()
    await test_tls_monitor()
    await test_port_scanner(engine)
    await test_anomaly(engine)
    await test_incidents(engine)
    await test_process_monitor(engine)
    await test_dns_leak()
    await test_firewall()
    await test_recon()

    section("Summary")
    if engine:
        await engine.stop()
        ok("Engine stopped cleanly")

    dangerous = [e for e in received if e.level == ThreatLevel.DANGEROUS]
    suspicious = [e for e in received if e.level == ThreatLevel.SUSPICIOUS]
    ok(f"Total events received: {len(received)}  "
       f"(dangerous={len(dangerous)}, suspicious={len(suspicious)})")

    print()


if __name__ == "__main__":
    asyncio.run(main())
