"""
Maze Guard detection test suite.
Run as root (needs raw sockets for scapy):
    sudo python3 tests/test_detections.py

Tests:
  1. Internet connectivity
  2. ARP spoof detection
  3. Port scan detection (suspicious at threshold, dangerous at 3x)
"""
import os
import subprocess
import sys
import time

TARGET_IP   = "192.168.0.26"    # this machine's Ethernet IP
TARGET_MAC  = None              # auto-detected below
IFACE       = "enp42s0"
GATEWAY_IP  = "192.168.0.1"
GATEWAY_MAC = "fc:4a:e9:66:3d:d4"
FAKE_MAC    = "de:ad:be:ef:00:01"
ATTACKER_IP = "192.168.0.77"    # fake attacker IP (not on LAN)

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
WARN = "\033[93m[WARN]\033[0m"


def _get_own_mac() -> str:
    try:
        return open(f"/sys/class/net/{IFACE}/address").read().strip()
    except Exception:
        return "ff:ff:ff:ff:ff:ff"


# ── 1. Internet connectivity ──────────────────────────────────────────────────

def test_internet():
    print(f"\n{INFO} Test 1: Internet connectivity")
    result = subprocess.run(
        ["curl", "-s", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}",
         "https://1.1.1.1"],
        capture_output=True, text=True,
    )
    code = result.stdout.strip()
    if code in ("200", "301", "302", "400", "403"):
        print(f"  HTTP {code} from 1.1.1.1")
        print(f"  {PASS} Internet is working")
        return True
    else:
        print(f"  HTTP {code or 'no response'} — internet appears blocked")
        print(f"  {WARN} Active firewall rules (check firewalld manually):")
        # Direct firewall-cmd call removed — would trigger polkit prompt.
        # Use `sudo firewall-cmd --list-all` from a terminal instead.
        return False


# ── 2. ARP spoof ──────────────────────────────────────────────────────────────

def test_arp_spoof():
    print(f"\n{INFO} Test 2: ARP spoof detection")
    print(f"  Sending fake ARP reply: {GATEWAY_IP} is-at {FAKE_MAC}")
    try:
        from scapy.all import ARP, Ether, sendp
        own_mac = _get_own_mac()
        # Gratuitous ARP reply claiming gateway IP has a new MAC
        pkt = (
            Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc=GATEWAY_IP, hwsrc=FAKE_MAC, pdst="0.0.0.0", hwdst="00:00:00:00:00:00")
        )
        sendp(pkt, iface=IFACE, verbose=False, count=3)
        print(f"  Sent gratuitous ARP (3x). Check Events tab for ARP_SPOOF.")
        print(f"  {PASS} (manual check needed — should appear as DANGEROUS in GUI)")
    except Exception as e:
        print(f"  {FAIL} {e}")


# ── 3a. Port scan — suspicious ────────────────────────────────────────────────

def test_port_scan_suspicious(threshold: int = 10):
    print(f"\n{INFO} Test 3a: Port scan — SUSPICIOUS at threshold ({threshold} SYNs)")
    try:
        from scapy.all import IP, TCP, Ether, sendp
        own_mac = _get_own_mac()
        pkts = []
        for port in range(1000, 1000 + threshold):
            pkt = (
                Ether(src=FAKE_MAC, dst=own_mac) /
                IP(src=ATTACKER_IP, dst=TARGET_IP) /
                TCP(dport=port, sport=54321, flags="S", seq=1000)
            )
            pkts.append(pkt)
        from scapy.all import sendp
        sendp(pkts, iface=IFACE, verbose=False, inter=0.05)
        print(f"  Sent {threshold} SYN packets from {ATTACKER_IP} via {IFACE}")
        print(f"  Expected: SUSPICIOUS event, no block")
        print(f"  {PASS} (check Events + Dashboard > Scan Detection)")
    except Exception as e:
        print(f"  {FAIL} {e}")


# ── 3b. Port scan — dangerous ─────────────────────────────────────────────────

def test_port_scan_dangerous(threshold: int = 10):
    count = threshold * 3 + 1
    attacker2 = "192.168.0.88"
    print(f"\n{INFO} Test 3b: Port scan — DANGEROUS at 3x threshold ({count} SYNs)")
    try:
        from scapy.all import IP, TCP, Ether, sendp
        own_mac = _get_own_mac()
        pkts = []
        for i in range(count):
            port = 2000 + (i % 63535)
            pkt = (
                Ether(src=FAKE_MAC, dst=own_mac) /
                IP(src=attacker2, dst=TARGET_IP) /
                TCP(dport=port, sport=54322, flags="S", seq=1000)
            )
            pkts.append(pkt)
        sendp(pkts, iface=IFACE, verbose=False, inter=0.02)
        print(f"  Sent {count} SYN packets from {attacker2}")
        print(f"  Expected: DANGEROUS event + tray notification + block")
        print(f"  {PASS} (check Events tab and system tray)")
    except Exception as e:
        print(f"  {FAIL} {e}")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.getuid() != 0:
        print("Run with sudo:")
        print("  sudo python3 tests/test_detections.py")
        sys.exit(1)

    print("=" * 60)
    print("  Maze Guard Detection Test Suite")
    print(f"  Target: {TARGET_IP} on {IFACE}")
    print("=" * 60)

    test_internet()
    test_arp_spoof()

    print(f"\n{INFO} Waiting 2s...")
    time.sleep(2)
    test_port_scan_suspicious()

    print(f"\n{INFO} Waiting 3s...")
    time.sleep(3)
    test_port_scan_dangerous()

    print("\n" + "=" * 60)
    print("  Done. Check Maze Guard GUI Events tab.")
    print("=" * 60)
