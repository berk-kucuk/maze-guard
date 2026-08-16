"""
Attacker dossiers: what Maze Guard knows about each hostile source.

Events are transient — they scroll off the event list and die with the process.
An incident is the durable side of the same story: every source that has done
something hostile gets one record collecting its identity (MAC, vendor,
hostname, OS), everything it was seen doing, the recon we ran against it, and
what we did about it. That record is written to disk, so evidence outlives both
the attack and the app.
"""
import json
import os
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from maze.core.events import Event, EventType, ThreatLevel
from maze.utils.logger import log

DATA_DIR = Path(os.environ.get("MAZE_DATA_DIR",
                               Path.home() / ".local" / "share" / "maze-guard"))

# How much each kind of observation says about hostile intent. ARP spoofing and
# a full port scan are attacks; an unknown process or a single odd TLS cert is
# worth recording but is routinely benign, so it barely moves the needle.
SCORE_WEIGHTS: dict[EventType, float] = {
    EventType.ARP_SPOOF:       45.0,
    EventType.ROGUE_AP:        40.0,
    EventType.ROGUE_DHCP:      40.0,
    EventType.DNS_SPOOF:       40.0,
    EventType.SSL_STRIP:       35.0,
    EventType.PORT_SCAN:       25.0,
    EventType.STEALTH_SCAN:    30.0,
    EventType.HOST_SWEEP:      15.0,
    EventType.ARP_SCAN:        12.0,
    EventType.TLS_CHANGE:      10.0,
    EventType.UNKNOWN_PROCESS:  3.0,
    EventType.RECON_RESULT:     0.0,
    EventType.DEVICE_FOUND:     0.0,
}

# Score halves after this long without any new activity, so a host that
# attacked once last week does not stay pinned at the top of the list forever.
_HALF_LIFE = timedelta(minutes=30)

_MAX_EVIDENCE = 200          # per attacker, in memory and on disk
_MAX_ATTACKERS = 500         # oldest-idle records are evicted past this
_SAVE_INTERVAL = 10.0        # seconds between snapshot rewrites

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _severity_for(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "info"


@dataclass
class Evidence:
    ts: datetime
    kind: str
    level: str
    message: str
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ts": self.ts.isoformat(), "kind": self.kind,
                "level": self.level, "message": self.message,
                "data": _jsonable(self.data)}

    @staticmethod
    def from_dict(d: dict) -> "Evidence":
        return Evidence(
            ts=_parse_ts(d.get("ts")), kind=d.get("kind", ""),
            level=d.get("level", ""), message=d.get("message", ""),
            data=d.get("data", {}),
        )


@dataclass
class Attacker:
    """Everything known about one hostile source address."""
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    os_hint: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    raw_score: float = 0.0
    scored_at: datetime = field(default_factory=datetime.now)
    techniques: set = field(default_factory=set)
    ports_targeted: set = field(default_factory=set)
    open_ports: list = field(default_factory=list)
    banners: dict = field(default_factory=dict)
    packets: int = 0
    blocked: bool = False
    recon: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    evidence: deque = field(default_factory=lambda: deque(maxlen=_MAX_EVIDENCE))

    # ── scoring ───────────────────────────────────────────────────────────

    def score(self, now: datetime | None = None) -> float:
        """Current score, decayed for time since the last scoring event."""
        now = now or datetime.now()
        idle = (now - self.scored_at).total_seconds()
        if idle <= 0:
            return round(self.raw_score, 1)
        decay = 0.5 ** (idle / _HALF_LIFE.total_seconds())
        return round(self.raw_score * decay, 1)

    @property
    def severity(self) -> str:
        return _severity_for(self.score())

    def add_score(self, points: float, now: datetime | None = None) -> None:
        now = now or datetime.now()
        # Fold the decayed value forward before adding, so repeated hits
        # accumulate but old ones still fade.
        self.raw_score = min(100.0, self.score(now) + points)
        self.scored_at = now

    # ── serialisation ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "hostname": self.hostname, "os_hint": self.os_hint,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "raw_score": self.raw_score,
            "scored_at": self.scored_at.isoformat(),
            "score": self.score(), "severity": self.severity,
            "techniques": sorted(self.techniques),
            "ports_targeted": sorted(self.ports_targeted),
            "open_ports": self.open_ports, "banners": _jsonable(self.banners),
            "packets": self.packets, "blocked": self.blocked,
            "recon": _jsonable(self.recon), "actions": self.actions,
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @staticmethod
    def from_dict(d: dict) -> "Attacker":
        a = Attacker(ip=d.get("ip", ""))
        a.mac = d.get("mac", "")
        a.vendor = d.get("vendor", "")
        a.hostname = d.get("hostname", "")
        a.os_hint = d.get("os_hint", "")
        a.first_seen = _parse_ts(d.get("first_seen"))
        a.last_seen = _parse_ts(d.get("last_seen"))
        a.raw_score = float(d.get("raw_score", d.get("score", 0.0)))
        a.scored_at = _parse_ts(d.get("scored_at", d.get("last_seen")))
        a.techniques = set(d.get("techniques", []))
        a.ports_targeted = set(d.get("ports_targeted", []))
        a.open_ports = d.get("open_ports", [])
        a.banners = d.get("banners", {})
        a.packets = int(d.get("packets", 0))
        a.blocked = bool(d.get("blocked", False))
        a.recon = d.get("recon", {})
        a.actions = d.get("actions", [])
        for ev in d.get("evidence", [])[-_MAX_EVIDENCE:]:
            a.evidence.append(Evidence.from_dict(ev))
        return a

    # ── reporting ─────────────────────────────────────────────────────────

    def report(self) -> str:
        """Human-readable incident report, suitable for filing or pasting."""
        lines = [
            f"# Maze Guard incident report — {self.ip}",
            "",
            f"Generated:   {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"Severity:    {self.severity.upper()}  (score {self.score()}/100)",
            f"First seen:  {self.first_seen:%Y-%m-%d %H:%M:%S}",
            f"Last seen:   {self.last_seen:%Y-%m-%d %H:%M:%S}",
            f"Blocked:     {'yes' if self.blocked else 'no'}",
            "",
            "## Identity",
            f"- IP address: {self.ip}",
            f"- MAC:        {self.mac or 'unknown'}"
            + (f"  ({self.vendor})" if self.vendor else ""),
            f"- Hostname:   {self.hostname or 'unknown'}",
            f"- OS guess:   {self.os_hint or 'unknown'}",
            "",
            "## Activity",
            f"- Techniques:  {', '.join(sorted(self.techniques)) or 'none recorded'}",
            f"- Packets:     {self.packets}",
        ]
        if self.ports_targeted:
            ports = sorted(self.ports_targeted)
            shown = ", ".join(str(p) for p in ports[:40])
            more = f" (+{len(ports) - 40} more)" if len(ports) > 40 else ""
            lines.append(f"- Ports probed on us ({len(ports)}): {shown}{more}")
        if self.open_ports:
            lines.append("")
            lines.append("## Services exposed by the source")
            for entry in self.open_ports:
                port, name = (entry if isinstance(entry, (list, tuple))
                              else (entry, "?"))
                banner = self.banners.get(str(port)) or self.banners.get(port)
                lines.append(f"- {port}/{name}" + (f" — {banner}" if banner else ""))
        if self.actions:
            lines.append("")
            lines.append("## Actions taken")
            for act in self.actions:
                lines.append(f"- {act.get('ts', '')}  {act.get('what', '')}")
        lines.append("")
        lines.append("## Timeline")
        for ev in self.evidence:
            lines.append(f"- {ev.ts:%Y-%m-%d %H:%M:%S}  [{ev.level}] "
                         f"{ev.kind}: {ev.message}")
        lines.append("")
        return "\n".join(lines)


class IncidentStore:
    """In-memory dossiers with a write-behind copy on disk.

    Thread-safety: the GUI paints from this while the event bus writes to it, so
    every mutation takes the lock and readers get snapshots, never live objects.
    """

    def __init__(self, data_dir: Path | None = None, autosave: bool = True):
        self._dir = Path(data_dir) if data_dir else DATA_DIR
        self._attackers: dict[str, Attacker] = {}
        self._lock = threading.RLock()
        self._autosave = autosave
        self._dirty = False
        self._last_save = 0.0
        self.load()

    # ── paths ─────────────────────────────────────────────────────────────

    @property
    def state_path(self) -> Path:
        return self._dir / "incidents.json"

    @property
    def journal_path(self) -> Path:
        return self._dir / "incidents.log"

    # ── ingest ────────────────────────────────────────────────────────────

    def record(self, event: Event) -> Attacker | None:
        """Fold one event into the dossier of whatever source it names.

        Returns the updated Attacker, or None when the event names no source
        (module toggles, profile switches and the like).
        """
        ip = _source_of(event)
        if not ip:
            return None
        weight = SCORE_WEIGHTS.get(event.type, 0.0)
        if weight == 0.0 and event.level == ThreatLevel.SAFE:
            return None                    # nothing hostile to record yet

        now = event.timestamp or datetime.now()
        with self._lock:
            att = self._attackers.get(ip)
            if att is None:
                att = Attacker(ip=ip, first_seen=now, last_seen=now,
                               scored_at=now)
                self._attackers[ip] = att
            att.last_seen = max(att.last_seen, now)

            data = event.data or {}
            att.mac = data.get("mac") or data.get("new_mac") or att.mac
            att.hostname = data.get("hostname") or att.hostname
            att.vendor = data.get("vendor") or att.vendor
            att.os_hint = data.get("os_hint") or att.os_hint
            if data.get("technique"):
                att.techniques.add(str(data["technique"]))
            else:
                att.techniques.add(event.type.value)
            for p in data.get("ports", []) or []:
                try:
                    att.ports_targeted.add(int(p))
                except (TypeError, ValueError):
                    pass
            att.packets += int(data.get("packets", 0) or 0)

            # A repeat of the same technique is worth less than a new one: the
            # second thousand SYNs tell us nothing the first hundred did not.
            repeat = event.type.value in {e.kind for e in att.evidence}
            att.add_score(weight * (0.25 if repeat else 1.0), now)

            att.evidence.append(Evidence(
                ts=now, kind=event.type.value, level=event.level.value,
                message=event.message, data=_jsonable(data),
            ))
            self._dirty = True
            self._journal(att, event)
            self._evict_if_needed()
            snapshot = att
        self._maybe_save()
        return snapshot

    def attach_recon(self, ip: str, recon: dict) -> Attacker | None:
        """Merge an active-recon result into the dossier."""
        with self._lock:
            att = self._attackers.get(ip)
            if att is None:
                att = Attacker(ip=ip)
                self._attackers[ip] = att
            att.recon = _jsonable(recon)
            att.mac = recon.get("mac") or att.mac
            att.vendor = recon.get("vendor") or att.vendor
            att.hostname = (recon.get("netbios_name") or recon.get("hostname")
                            or att.hostname)
            att.os_hint = recon.get("os_hint") or att.os_hint
            att.open_ports = recon.get("open_ports") or att.open_ports
            if recon.get("banners"):
                att.banners = {str(k): v for k, v in recon["banners"].items()}
            # Attack tooling exposed on the source itself is corroboration, not
            # a new attack — a modest bump, not a whole new incident.
            if recon.get("risk_score"):
                att.add_score(min(15.0, float(recon["risk_score"]) / 4.0))
            self._dirty = True
        self._maybe_save()
        return self.get(ip)

    def add_action(self, ip: str, what: str) -> None:
        with self._lock:
            att = self._attackers.get(ip)
            if att is None:
                return
            att.actions.append({"ts": datetime.now().isoformat(timespec="seconds"),
                                "what": what})
            self._dirty = True
        # An action is a decision we took, not just something we observed:
        # write it out immediately rather than waiting for the next tick.
        self._maybe_save(force=True)

    def mark_blocked(self, ip: str, blocked: bool = True) -> None:
        with self._lock:
            att = self._attackers.get(ip)
            if att is None:
                return
            att.blocked = blocked
            self._dirty = True
        self.add_action(ip, "firewall block added" if blocked
                        else "firewall block removed")

    # ── query ─────────────────────────────────────────────────────────────

    def get(self, ip: str) -> Attacker | None:
        with self._lock:
            return self._attackers.get(ip)

    def all(self) -> list[Attacker]:
        """Dossiers, most threatening first."""
        with self._lock:
            items = list(self._attackers.values())
        return sorted(items, key=lambda a: (-a.score(), -a.last_seen.timestamp()))

    def active(self, within_minutes: int = 60) -> list[Attacker]:
        cutoff = datetime.now() - timedelta(minutes=within_minutes)
        return [a for a in self.all() if a.last_seen >= cutoff]

    def worst_severity(self, within_minutes: int = 60) -> str:
        best = "info"
        for a in self.active(within_minutes):
            if SEVERITY_ORDER.index(a.severity) > SEVERITY_ORDER.index(best):
                best = a.severity
        return best

    def clear(self, ip: str | None = None) -> None:
        with self._lock:
            if ip:
                self._attackers.pop(ip, None)
            else:
                self._attackers.clear()
            self._dirty = True
        self._maybe_save(force=True)

    # ── persistence ───────────────────────────────────────────────────────

    def _evict_if_needed(self) -> None:
        if len(self._attackers) <= _MAX_ATTACKERS:
            return
        stale = sorted(self._attackers.values(), key=lambda a: a.last_seen)
        for att in stale[: len(self._attackers) - _MAX_ATTACKERS]:
            self._attackers.pop(att.ip, None)

    def _journal(self, att: Attacker, event: Event) -> None:
        """Append-only evidence line. Written even if the snapshot save fails,
        because this file is what an investigation actually reads."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            line = json.dumps({
                "ts": (event.timestamp or datetime.now()).isoformat(),
                "ip": att.ip, "kind": event.type.value,
                "level": event.level.value, "score": att.score(),
                "message": event.message, "data": _jsonable(event.data or {}),
            }, ensure_ascii=False)
            with open(self.journal_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._rotate_journal()
        except Exception as exc:
            log.debug(f"incident journal write failed: {exc}")

    def _rotate_journal(self, max_bytes: int = 4 * 1024 * 1024) -> None:
        try:
            if self.journal_path.stat().st_size > max_bytes:
                self.journal_path.replace(self._dir / "incidents.log.1")
        except Exception:
            pass

    def _maybe_save(self, force: bool = False) -> None:
        """Rewrite the snapshot, but not on every single event.

        During a sustained attack the store is updated constantly; rewriting
        the whole file each time would turn a scan into a disk-I/O storm for no
        benefit. Durability does not depend on this — every observation is
        already in the append-only journal — so the snapshot can lag a little.
        """
        if not self._autosave:
            return
        now = time.monotonic()
        if not force and now - self._last_save < _SAVE_INTERVAL:
            return
        self._last_save = now
        self.save()

    def save(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            payload = {"version": 1,
                       "saved_at": datetime.now().isoformat(),
                       "attackers": [a.to_dict() for a in self._attackers.values()]}
            self._dirty = False
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            # Atomic replace: a crash mid-write must not leave a truncated file
            # that loses every dossier on the next start.
            fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.state_path)
        except Exception as exc:
            log.warning(f"could not persist incidents: {exc}")

    def load(self) -> None:
        try:
            if not self.state_path.exists():
                return
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            with self._lock:
                for d in payload.get("attackers", []):
                    att = Attacker.from_dict(d)
                    if att.ip:
                        self._attackers[att.ip] = att
        except Exception as exc:
            log.warning(f"could not load incidents: {exc}")

    def export_report(self, ip: str, path: Path) -> bool:
        att = self.get(ip)
        if att is None:
            return False
        try:
            Path(path).write_text(att.report(), encoding="utf-8")
            return True
        except Exception as exc:
            log.warning(f"report export failed: {exc}")
            return False


# ── helpers ──────────────────────────────────────────────────────────────────

def _source_of(event: Event) -> str:
    data = event.data or {}
    for key in ("src", "ip", "remote_ip", "attacker"):
        val = data.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return datetime.now()


def _jsonable(obj):
    """Coerce event payloads into something json.dump will accept."""
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)
