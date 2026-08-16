#!/usr/bin/env python3
"""
Maze Guard self-test — proves the detection pipeline actually fires.

It injects a simulated port scan (SYN packets from a FAKE source IP to many
distinct ports) on the monitored interface. The running Maze Guard daemon sniffs
these and the GUI should raise a "Port scan detected" event.

100% safe:
  • The fake source is a made-up LAN IP that does not exist.
  • It sends just above the SUSPICIOUS threshold but below the DANGEROUS (3x)
    threshold, so NO IP gets auto-blocked and NO firewall rule is added.
  • No real host is contacted.

Run as root (raw sockets):
    sudo ./venv/bin/python maze_selftest.py
"""
import sys

def main() -> int:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    try:
        from scapy.all import IP, TCP, Ether, sendp, conf
    except Exception as e:
        print(f"[!] scapy import failed: {e}")
        return 1

    from maze.utils.network_info import get_active_physical_interface, get_interface_info
    from maze.utils.config import load_config

    iface = get_active_physical_interface()
    info  = get_interface_info(iface)
    own   = info.ip if info.ip != "—" else "192.168.0.1"

    cfg = load_config()
    threshold = getattr(cfg, "port_scan_threshold", 25)
    n_ports = threshold + 5           # ≥ threshold (SUSPICIOUS), < 3x (no block)

    fake_src = "192.168.0.234"        # nonexistent LAN host — the "attacker"
    if fake_src == own:
        fake_src = "192.168.0.235"

    print("=" * 58)
    print("  Maze Guard self-test — simulated port scan")
    print("=" * 58)
    print(f"  interface : {iface}")
    print(f"  target    : {own}")
    print(f"  attacker  : {fake_src} (fake)")
    print(f"  threshold : {threshold}  → sending {n_ports} SYNs to distinct ports")
    print("-" * 58)

    conf.verb = 0
    base = 20000
    # Explicit broadcast dst MAC so scapy does NOT try to ARP-resolve the
    # destination per packet (that was slow and spammed "MAC not found"). The
    # daemon sniffs promiscuously, so the L2 dst does not matter for detection.
    pkts = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=fake_src, dst=own)
        / TCP(sport=40000 + i, dport=base + i, flags="S")
        for i in range(n_ports)
    ]
    try:
        sendp(pkts, iface=iface, inter=0.02)
    except PermissionError:
        print("[!] Need root. Run:  sudo ./venv/bin/python maze_selftest.py")
        return 1
    except Exception as e:
        print(f"[!] send failed: {e}")
        return 1

    print(f"  ✓ Sent {n_ports} SYN packets from {fake_src}")
    print("-" * 58)
    print("  Now open Maze Guard → Events tab. Within a few seconds you")
    print("  should see:")
    print(f"     SUSPICIOUS · Port Scan · from {fake_src}")
    print("  and Dashboard → Scan Detection should list the attacker IP.")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    sys.exit(main())
