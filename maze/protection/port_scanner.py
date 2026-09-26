import asyncio
import threading
import time
from dataclasses import dataclass, field

from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import (FAIL, PASS, Verdict, WARN,
                              capture_feed, merge)
from maze.utils.logger import log

_WINDOW            = 300   # activity older than this stops counting (seconds)
_PRUNE_INTERVAL    = 30    # how often stale records are swept
_OWN_IP_REFRESH    = 60    # how often to re-read own interface IPs (seconds)
_RE_ALERT_AFTER    = 600   # same source may raise the same alert again after
_MAX_PORTS_TRACKED = 4096  # bound per-source memory against a full 65k sweep
_PORTS_IN_PAYLOAD  = 256   # how many of them travel with the event
# One direct-capture slice. Bounds how long stop() waits for the sniffing
# thread on an interface with no traffic.
_SNIFF_SLICE = 5
_MAX_TARGETS       = 256   # bound per-source memory for observed destinations
_MAX_RECORDS       = 4096  # bound the number of sources tracked at once

# TCP flag combinations that no normal client produces. A stack opens a
# connection with SYN and tears it down with FIN *after* an ACK-bearing
# exchange; a bare FIN, a header with no flags at all, or FIN+PSH+URG is a
# scanner probing for a response difference between open and closed ports.
_STEALTH_FLAGS = {
    "":    "null_scan",
    "F":   "fin_scan",
    "FPU": "xmas_scan",
    "FP":  "fin_psh_scan",
    "U":   "urg_scan",
    "P":   "psh_scan",
    "FU":  "fin_urg_scan",
}
# Ports so commonly hit by ordinary traffic that a couple of hits mean nothing.
_NOISY_PORTS = {80, 443, 53, 22, 123, 3478, 5353, 1900}


@dataclass
class ScanRecord:
    """Live evidence about one source address."""
    src: str
    first_seen: float
    last_seen: float
    ports: set = field(default_factory=set)
    targets: set = field(default_factory=set)
    techniques: set = field(default_factory=set)
    packets: int = 0
    stealth_packets: int = 0
    alerted_at: float = 0.0
    escalated_at: float = 0.0
    stealth_alerted_at: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.001, self.last_seen - self.first_seen)

    @property
    def rate(self) -> float:
        """Distinct ports probed per second — separates a slow, deliberate
        sweep from a tool running flat out."""
        return len(self.ports) / self.duration

    def summary(self) -> dict:
        return {
            "src": self.src,
            "unique_ports": len(self.ports),
            # A sample, not the whole set: the payload is journalled and shown
            # in the UI, so it stays bounded. `unique_ports` above carries the
            # real figure — anything reading this must count with that.
            "ports": sorted(self.ports)[:_PORTS_IN_PAYLOAD],
            "targets": sorted(self.targets)[:16],
            "techniques": sorted(self.techniques),
            "packets": self.packets,
            "stealth_packets": self.stealth_packets,
            "duration_s": round(self.duration, 1),
            "rate_pps": round(self.rate, 2),
        }


class PortScanDetector:
    """Detect and classify TCP reconnaissance against this host.

    Two independent signals, because they mean different things:

    * Breadth — a source touching many DISTINCT destination ports. Counting
      raw SYNs instead flagged heavy but perfectly normal traffic (CDN asset
      loading, bittorrent), so only distinct ports count here.
    * Technique — a probe whose TCP flags no real client would ever send
      (FIN, NULL, XMAS). That needs no volume at all to be meaningful: a
      handful of such packets is a stealth scan, full stop.

    Everything observed is retained per source as evidence, so the incident
    record can say what was probed, how fast, and with which technique — not
    just "a scan happened".
    """

    def __init__(self, interface: str, threshold: int = 25,
                 whitelist: list[str] | None = None):
        self.interface = interface
        self.threshold = max(3, threshold)
        self._whitelist  = set(whitelist or [])
        self._own_ips: set[str] = set()
        self._records: dict[str, ScanRecord] = {}
        self._blocked: set[str] = set()
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._prune_task: asyncio.Task | None = None
        self._own_ip_task: asyncio.Task | None = None
        self._stop_event = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._helper = None
        self._capture = ""      # "helper" | "direct" — where packets come from
        self._seen = 0          # probe packets accepted, for the self-test

    # ── introspection for the UI ──────────────────────────────────────────

    @property
    def blocked_ips(self) -> set[str]:
        return self._blocked

    def mark_blocked(self, ip: str) -> None:
        """Record that ``ip`` was firewall-blocked, so the dashboard scan
        table can show it as BLOCKED. Called by the engine after a block."""
        self._blocked.add(ip)

    @property
    def scan_attempts(self) -> dict[str, int]:
        return {k: len(v.ports) for k, v in self._records.items()}

    def records(self) -> list[ScanRecord]:
        return sorted(self._records.values(), key=lambda r: -len(r.ports))

    def status_detail(self) -> str:
        if self._capture == "direct":
            return ("capturing directly — needs root; without it no packets "
                    "are seen at all")
        if not self._own_ips:
            return ("this host's own addresses could not be read — traffic "
                    "aimed at other machines may be counted")
        return (f"threshold {self.threshold} ports · "
                f"{len(self._records)} sources being watched")

    async def verify(self) -> Verdict:
        """Prove both halves: that packets arrive, and that a scan trips it.

        Two independent things have to hold for this module to protect anyone,
        and each can fail while the other looks fine. The capture is checked by
        counting what has actually arrived. The analysis is checked by running
        a synthetic sweep through a throwaway detector built exactly like this
        one — no raw sockets, no traffic on the wire, nothing touched on the
        system, and the real code path from packet to alarm.
        """
        alarm = await self._selftest_alarm()
        feed = await capture_feed(self._helper, self._capture, self._seen,
                                  "connection probes aimed at this host")
        feed.evidence.append(
            f"this host's addresses: "
            f"{', '.join(sorted(self._own_ips)) or 'could not be read'}")
        if self._records:
            feed.evidence.append(f"{len(self._records)} sources being tracked")
        return merge(alarm, feed)

    async def _selftest_alarm(self) -> Verdict:
        """Feed a synthetic sweep through a disposable copy of this detector."""
        probe = PortScanDetector(self.interface, self.threshold)
        probe._own_ips = {"198.51.100.1"}          # TEST-NET-2, ours for this
        fired: list[Event] = []

        class _Sink(EventBus):
            async def emit(self, event):
                fired.append(event)

        probe._bus = _Sink()
        probe._loop = asyncio.get_event_loop()
        for port in range(1, self.threshold + 3):
            await probe._process("198.51.100.9", port, "S", "198.51.100.1")
        if not fired:
            return Verdict(FAIL,
                           f"the detector did NOT raise an alarm for a "
                           f"synthetic {self.threshold + 2}-port sweep — port "
                           f"scan detection is broken, not merely quiet")
        return Verdict(PASS,
                       f"a synthetic {self.threshold + 2}-port sweep raised "
                       f"'{fired[0].type.value}' as it should",
                       [fired[0].message])

    def evidence(self, src: str) -> dict | None:
        rec = self._records.get(src)
        return rec.summary() if rec else None

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus  = bus
        self._loop = asyncio.get_event_loop()
        self._helper = helper
        self._stop_event.clear()
        await self._refresh_own_ips()
        self._own_ip_task  = asyncio.create_task(self._own_ip_refresh_loop())
        self._prune_task   = asyncio.create_task(self._prune_loop())
        if helper and helper.is_connected():
            self._capture = "helper"
            helper.on_event(self._on_helper_event)
        else:
            self._capture = "direct"
            self._task = asyncio.create_task(self._run_direct())
            log.warning("PortScanDetector: helper unavailable, trying direct sniff")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._helper is not None:
            self._helper.off_event(self._on_helper_event)
        for t in (self._task, self._prune_task, self._own_ip_task):
            if t:
                t.cancel()

    async def _refresh_own_ips(self) -> None:
        from maze.detection.arp_watch import _get_own_ips
        self._own_ips = await asyncio.to_thread(_get_own_ips, self.interface)

    async def _own_ip_refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(_OWN_IP_REFRESH)
            await self._refresh_own_ips()

    async def _prune_loop(self) -> None:
        """Drop sources that have gone quiet.

        The old implementation cleared every counter on a fixed 5-minute tick,
        which handed a patient scanner a free reset: pace the probes across the
        boundary and no window ever reached the threshold. Ageing each source
        out individually removes that trick — the window now genuinely slides.
        """
        while True:
            await asyncio.sleep(_PRUNE_INTERVAL)
            cutoff = time.monotonic() - _WINDOW
            for src, rec in list(self._records.items()):
                if rec.last_seen < cutoff:
                    del self._records[src]

    # ── packet intake ─────────────────────────────────────────────────────

    async def _on_helper_event(self, msg: dict) -> None:
        kind = msg.get("event")
        if kind == "tcp":
            await self._process(msg.get("src"), msg.get("dport", 0),
                                msg.get("flags", "S"), msg.get("dst", ""))
        elif kind == "syn":     # older helper daemon
            await self._process(msg.get("src"), msg.get("dport", 0), "S",
                                msg.get("dst", ""))

    async def _run_direct(self) -> None:
        """Capture without the helper, in bounded slices.

        scapy only evaluates stop_filter when a packet arrives, so a single
        endless sniff() on a quiet interface cannot be stopped at all: the
        worker thread blocks until the next packet, and because it is not a
        daemon thread, quitting the application waits for it too. Slicing the
        capture bounds that wait to one interval.

        The BPF admits IPv6 as well. It has to be spelled out separately —
        libpcap cannot reach tcp[tcpflags] through a v6 header, so the flag
        byte is read at its literal offset (40 bytes of IPv6 header + 13).
        """
        try:
            from scapy.all import TCP, IP, IPv6, sniff
        except Exception as exc:
            log.warning(f"PortScanDetector: scapy unavailable — {exc}")
            return

        bpf = ("(tcp and tcp[tcpflags] & tcp-ack = 0)"
               " or (ip6 and tcp and ip6[53] & 0x10 = 0)")

        def _on_pkt(pkt):
            if not pkt.haslayer(TCP):
                return
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                return
            asyncio.run_coroutine_threadsafe(
                self._process(src, pkt[TCP].dport, str(pkt[TCP].flags), dst),
                self._loop)

        loop = asyncio.get_event_loop()
        while not self._stop_event.is_set():
            try:
                await loop.run_in_executor(
                    None,
                    lambda: sniff(
                        iface=self.interface,
                        filter=bpf,
                        prn=_on_pkt,
                        store=False,
                        timeout=_SNIFF_SLICE,
                        stop_filter=lambda _: self._stop_event.is_set(),
                    ),
                )
            except Exception as e:
                log.warning(f"PortScanDetector sniff error: {e}")
                return

    # ── analysis ──────────────────────────────────────────────────────────

    async def _process(self, src: str | None, dport: int = 0,
                       flags: str = "S", dst: str = "") -> None:
        if not src:
            return
        if src in self._whitelist or src in self._own_ips:
            return

        # Only traffic aimed at THIS host is evidence of a scan against us.
        #
        # The capture runs in promiscuous mode, so on a bridged VM host, a
        # mirrored switch port or an old-style shared segment we also see
        # conversations between other machines. Counting those made a busy
        # neighbour — or the very server we were downloading from — look like
        # it was sweeping our ports. Sweeps aimed at the network as a whole are
        # still caught, by the anomaly detector, which is the module whose job
        # that is. When our own addresses cannot be read the check is skipped
        # rather than dropping everything: a detector that silently sees no
        # traffic is worse than one that sees a little too much.
        if dst and self._own_ips and dst not in self._own_ips:
            return

        technique = _classify(flags)
        is_probe = _is_syn_probe(flags)
        if not technique and not is_probe:
            # Part of a conversation we are already in (anything carrying ACK)
            # or a reset. A server resetting one of our ephemeral ports is not
            # scanning us — but because every connection uses a *new* ephemeral
            # port, counting those ports was enough on its own to push ordinary
            # browsing past the breadth threshold.
            return

        now = time.monotonic()
        rec = self._records.get(src)
        if rec is None:
            self._evict_if_needed()
            rec = ScanRecord(src=src, first_seen=now, last_seen=now)
            self._records[src] = rec
        self._seen += 1
        rec.last_seen = now
        rec.packets += 1
        if dst and len(rec.targets) < _MAX_TARGETS:
            rec.targets.add(dst)
        if len(rec.ports) < _MAX_PORTS_TRACKED:
            rec.ports.add(int(dport or 0))

        if technique:
            rec.techniques.add(technique)
            rec.stealth_packets += 1
            await self._maybe_alert_stealth(rec, technique, now)
            return

        rec.techniques.add("syn_scan")
        await self._maybe_alert_breadth(rec, now)

    def _evict_if_needed(self) -> None:
        """Keep the record table bounded.

        A spoofed-source scan invents a new address per packet, so without this
        a single burst could grow the table without limit in a process that is
        expected to run for weeks. The quietest sources go first.
        """
        if len(self._records) < _MAX_RECORDS:
            return
        stale = sorted(self._records.values(), key=lambda r: r.last_seen)
        for rec in stale[: len(self._records) - _MAX_RECORDS + 1]:
            self._records.pop(rec.src, None)

    async def _maybe_alert_stealth(self, rec: ScanRecord, technique: str,
                                   now: float) -> None:
        """Stealth probes need volume only to rule out a single stray packet."""
        if rec.stealth_packets < 3:
            return
        if now - rec.stealth_alerted_at < _RE_ALERT_AFTER:
            return
        rec.stealth_alerted_at = now
        data = rec.summary()
        data["technique"] = technique
        await self._bus.emit(Event(
            type=EventType.STEALTH_SCAN,
            level=ThreatLevel.DANGEROUS,
            message=(f"Stealth scan from {rec.src} "
                     f"({technique.replace('_', ' ')}, "
                     f"{rec.stealth_packets} probes, "
                     f"{len(rec.ports)} ports) — these flags are never sent by "
                     f"normal clients"),
            data=data,
        ))

    async def _maybe_alert_breadth(self, rec: ScanRecord, now: float) -> None:
        # Ports every machine talks to anyway shouldn't count toward breadth.
        meaningful = len(rec.ports - _NOISY_PORTS)
        if meaningful < self.threshold:
            return

        data = rec.summary()
        data["technique"] = "syn_scan"
        fast = rec.rate >= 5.0

        if meaningful >= self.threshold * 3:
            if now - rec.escalated_at < _RE_ALERT_AFTER:
                return
            rec.escalated_at = now
            rec.alerted_at = now
            await self._bus.emit(Event(
                type=EventType.PORT_SCAN,
                level=ThreatLevel.DANGEROUS,
                message=(f"Port scan attack from {rec.src} — {meaningful} ports "
                         f"in {_fmt_duration(rec.duration)}"
                         f"{' (high rate)' if fast else ''}"),
                data=data,
            ))
        else:
            if now - rec.alerted_at < _RE_ALERT_AFTER:
                return
            rec.alerted_at = now
            await self._bus.emit(Event(
                type=EventType.PORT_SCAN,
                level=ThreatLevel.SUSPICIOUS,
                message=(f"Port scan detected from {rec.src} "
                         f"({meaningful} distinct ports probed)"),
                data=data,
            ))


def _fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return "under a second"
    if seconds < 90:
        return f"{seconds:.0f}s"
    return f"{seconds / 60:.0f}m"


def _classify(flags: str) -> str:
    """Map a TCP flag string to a stealth-scan technique, or "" if ordinary.

    scapy renders flags as letters (S, FPU, ...). Anything carrying ACK is
    part of a real conversation and is not classified here.
    """
    f = (flags or "").upper()
    if "A" in f or "R" in f:
        return ""          # belongs to a real conversation, or is a reset
    if "S" in f:
        return ""          # ordinary SYN — measured as breadth, not technique
    return _STEALTH_FLAGS.get(f, "")


def _is_syn_probe(flags: str) -> bool:
    """Whether this packet is a bare connection attempt.

    Breadth is only meaningful for these. `_classify` deliberately answers ""
    for both a plain SYN and a reset, and the two used to be handled the same
    way further down — so every RST a server sent us was filed as one more
    "port probed", with the port being our own ephemeral source port.
    """
    f = (flags or "").upper()
    return "S" in f and "A" not in f and "R" not in f
