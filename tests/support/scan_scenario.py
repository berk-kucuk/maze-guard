"""
The real detection path, driven by real packets.

Runs inside an unprivileged user + network namespace (`unshare -Urn`), where
this process is root as far as the kernel is concerned but powerless outside
it. That buys a private loopback interface and the raw-socket capability scapy
needs — so the capture, the classification and the alert are all the production
code paths, not stubs, and no test needs sudo.

The scenario:

  * 127.0.0.2 stands in for the attacker, 127.0.0.1 for this host,
  * twenty TCP connections are opened to closed ports on 127.0.0.1,
  * the real PortScanDetector, sniffing the real interface, has to notice.

Prints one JSON object for the test to assert on.
"""
import asyncio
import json
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from maze.core.events import EventBus, ThreatLevel        # noqa: E402
from maze.protection.port_scanner import PortScanDetector  # noqa: E402

ATTACKER = "127.0.0.2"
TARGET = "127.0.0.1"
THRESHOLD = 5
PORTS = range(9000, 9020)


class _Collector(EventBus):
    def __init__(self):
        super().__init__()
        self.events = []

    async def emit(self, event):
        self.events.append(event)
        await super().emit(event)


def _setup_namespace() -> None:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    # A second loopback address to scan *from*: without it the source and the
    # destination are the same address, and "traffic we sent ourselves" is
    # exactly what the detector is supposed to ignore.
    subprocess.run(["ip", "addr", "add", f"{ATTACKER}/8", "dev", "lo"],
                   stderr=subprocess.DEVNULL)


def _scan() -> None:
    for port in PORTS:
        sock = socket.socket()
        sock.settimeout(0.05)
        try:
            sock.bind((ATTACKER, 0))
            sock.connect((TARGET, port))
        except OSError:
            pass
        finally:
            sock.close()


async def main() -> int:
    _setup_namespace()
    bus = _Collector()
    detector = PortScanDetector("lo", threshold=THRESHOLD)
    await detector.start(bus, helper=None)      # no helper → direct capture
    # Inside one namespace both addresses genuinely belong to this host, and
    # "traffic we sent ourselves" is exactly what the detector must ignore.
    # Narrowing the set to the target is what makes 127.0.0.2 a stranger — the
    # only fiction in the scenario, and the one being simulated.
    detector._own_ips = {TARGET}
    await asyncio.sleep(1.0)                    # let the sniffer attach

    await asyncio.to_thread(_scan)
    for _ in range(60):                         # up to 6s for the alert
        if bus.events:
            break
        await asyncio.sleep(0.1)
    await asyncio.sleep(0.5)
    await detector.stop()

    print(json.dumps({
        "capture": detector._capture,
        "packets_seen": detector._seen,
        "events": [
            {"type": e.type.value, "level": e.level.value,
             "src": e.data.get("src", ""), "unique_ports": e.data.get("unique_ports", 0),
             "technique": e.data.get("technique", "")}
            for e in bus.events
        ],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
