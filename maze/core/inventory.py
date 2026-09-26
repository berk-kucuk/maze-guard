"""
A memory of which devices belong on which network.

The ARP watcher already says "new device: 192.168.0.28 (da:38:63:…)" — but
"new" there means new since this process started, so every restart makes every
neighbour new again, and the message is noise. What a person actually wants to
know is narrower and much more useful: *something that has never been on this
network before just joined it.*

Three decisions make that answerable:

  * **Keyed by MAC, not IP.** An IP is a DHCP lease. The MAC is the device.
  * **Scoped per network.** Identity is the SSID (or the gateway's MAC on
    wired), so a phone that belongs at home is still a stranger at a café.
    Modern phones randomise their MAC, but they do it *per network and keep it*
    — the randomised address is stable for as long as it stays joined, which is
    exactly the scope this baseline uses.
  * **A learning window.** The first time we see a network we have no idea
    what belongs there, so nothing is reported for a couple of minutes; the
    devices found in that window become the baseline. Without it, opening the
    app on an unfamiliar network would fire an alert per neighbour.

The inventory is persisted, unlike the recon cache: this is the one thing here
that is *supposed* to outlive both the session and the lease.
"""
import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from maze.utils.logger import log

def default_data_dir() -> Path:
    """Where the inventory lives — resolved per call so tests and packaged
    runs can redirect it without import-order games."""
    return Path(os.environ.get("MAZE_DATA_DIR",
                               Path.home() / ".local" / "share" / "maze-guard"))

# How long a network we have never seen before is treated as unknown territory:
# devices found in this window are recorded silently as the baseline.
LEARN_WINDOW = 120.0

# Bound the file. Networks and devices are both cheap, but a laptop that visits
# a lot of public WiFi should not grow this without limit.
_MAX_DEVICES_PER_NETWORK = 512
_MAX_NETWORKS = 64
_MAX_IPS_PER_DEVICE = 8
_SAVE_INTERVAL = 5.0


def _now() -> datetime:
    return datetime.now()


@dataclass
class DeviceRecord:
    """One device, as known on one network."""
    mac: str
    network_id: str
    ips: list = field(default_factory=list)     # most recently seen first
    vendor: str = ""
    kind: str = ""                              # from reconnaissance
    name: str = ""                              # discovered (NetBIOS/mDNS/UPnP)
    label: str = ""                             # assigned by the user
    trusted: bool = False                       # "yes, this one belongs here"
    randomized_mac: bool = False
    times_seen: int = 0
    first_seen: datetime = field(default_factory=_now)
    last_seen: datetime = field(default_factory=_now)

    @property
    def display_name(self) -> str:
        return self.label or self.name or self.vendor or self.mac

    @property
    def ip(self) -> str:
        return self.ips[0] if self.ips else ""

    def to_dict(self) -> dict:
        return {
            "mac": self.mac, "network_id": self.network_id, "ips": self.ips,
            "vendor": self.vendor, "kind": self.kind, "name": self.name,
            "label": self.label, "trusted": self.trusted,
            "randomized_mac": self.randomized_mac,
            "times_seen": self.times_seen,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    @staticmethod
    def from_dict(d: dict) -> "DeviceRecord":
        rec = DeviceRecord(mac=d.get("mac", ""),
                           network_id=d.get("network_id", ""))
        rec.ips = list(d.get("ips", []))[:_MAX_IPS_PER_DEVICE]
        rec.vendor = d.get("vendor", "")
        rec.kind = d.get("kind", "")
        rec.name = d.get("name", "")
        rec.label = d.get("label", "")
        rec.trusted = bool(d.get("trusted", False))
        rec.randomized_mac = bool(d.get("randomized_mac", False))
        rec.times_seen = int(d.get("times_seen", 0) or 0)
        rec.first_seen = _parse_ts(d.get("first_seen"))
        rec.last_seen = _parse_ts(d.get("last_seen"))
        return rec


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return _now()


def _norm(mac: str) -> str:
    return (mac or "").strip().lower()


# Locally-administered bit — set by MAC randomisation.
def _is_randomized(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


class DeviceInventory:
    """Persistent per-network device baseline.

    Thread-safety mirrors IncidentStore: the sniff thread's events and the GUI
    read the same records, so every mutation takes the lock.
    """

    def __init__(self, data_dir: Path | None = None, autosave: bool = True,
                 learn_window: float = LEARN_WINDOW):
        self._dir = Path(data_dir) if data_dir else default_data_dir()
        self._autosave = autosave
        self._learn_window = learn_window
        self._lock = threading.RLock()
        self._devices: dict[tuple[str, str], DeviceRecord] = {}
        self._networks: dict[str, dict] = {}     # network_id → {first_seen, learning_until}
        self._labels: dict[str, str] = {}        # mac → label, across networks
        self._dirty = False
        self._saved_at = 0.0
        self.load()

    # ── paths ────────────────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        return self._dir / "devices.json"

    # ── observation ──────────────────────────────────────────────────────

    def observe(self, mac: str, ip: str, network_id: str) -> tuple[DeviceRecord | None, bool]:
        """Record that ``mac`` is present on ``network_id``.

        Returns (record, is_new_here) where is_new_here is True only when this
        device has never been seen on this network AND the network's learning
        window has closed — i.e. exactly when it is worth telling someone.
        """
        mac = _norm(mac)
        if not mac or not network_id:
            return None, False

        with self._lock:
            learning = self._touch_network(network_id)
            key = (network_id, mac)
            rec = self._devices.get(key)
            if rec is None:
                rec = DeviceRecord(mac=mac, network_id=network_id,
                                   randomized_mac=_is_randomized(mac),
                                   label=self._labels.get(mac, ""))
                # Devices present while we are still learning the network are
                # the baseline, not an event.
                rec.trusted = learning
                self._devices[key] = rec
                self._evict(network_id)
                is_new = not learning
            else:
                is_new = False

            rec.last_seen = _now()
            rec.times_seen += 1
            if ip:
                if ip in rec.ips:
                    rec.ips.remove(ip)
                rec.ips.insert(0, ip)
                del rec.ips[_MAX_IPS_PER_DEVICE:]
            self._dirty = True

        self._maybe_save()
        return rec, is_new

    def _touch_network(self, network_id: str) -> bool:
        """Register a network and report whether it is still being learned."""
        net = self._networks.get(network_id)
        now = time.time()
        if net is None:
            if len(self._networks) >= _MAX_NETWORKS:
                oldest = min(self._networks, key=lambda n: self._networks[n].get("last_seen", 0))
                self._forget_network(oldest)
            self._networks[network_id] = {
                "first_seen": _now().isoformat(),
                "learning_until": now + self._learn_window,
                "last_seen": now,
            }
            self._dirty = True
            # A zero window means "treat this network as already known", which
            # is what a caller asks for when it wants every arrival reported.
            return self._learn_window > 0
        net["last_seen"] = now
        return now < float(net.get("learning_until", 0))

    def is_learning(self, network_id: str) -> bool:
        with self._lock:
            net = self._networks.get(network_id)
            return bool(net and time.time() < float(net.get("learning_until", 0)))

    # ── enrichment ───────────────────────────────────────────────────────

    def enrich(self, mac: str, network_id: str, *, vendor: str = "",
               kind: str = "", name: str = "") -> None:
        """Fold in what reconnaissance learned. Never overwrites with blanks."""
        with self._lock:
            rec = self._devices.get((network_id, _norm(mac)))
            if rec is None:
                return
            rec.vendor = vendor or rec.vendor
            rec.kind = kind or rec.kind
            rec.name = name or rec.name
            self._dirty = True
        self._maybe_save()

    # ── user decisions ───────────────────────────────────────────────────

    def set_label(self, mac: str, network_id: str, label: str) -> None:
        """Name a device. The name follows the MAC to every network, because a
        device the user has named is the same device wherever it turns up."""
        mac = _norm(mac)
        with self._lock:
            label = label.strip()[:60]
            if label:
                self._labels[mac] = label
            else:
                self._labels.pop(mac, None)
            for (net, m), rec in self._devices.items():
                if m == mac:
                    rec.label = label
            self._dirty = True
        self.save()

    def set_trusted(self, mac: str, network_id: str, trusted: bool = True) -> None:
        with self._lock:
            rec = self._devices.get((network_id, _norm(mac)))
            if rec is None:
                return
            rec.trusted = trusted
            self._dirty = True
        self.save()

    def forget(self, mac: str, network_id: str) -> None:
        with self._lock:
            self._devices.pop((network_id, _norm(mac)), None)
            self._dirty = True
        self.save()

    def forget_network(self, network_id: str) -> None:
        """Drop a network's baseline. The next visit is learned from scratch."""
        with self._lock:
            self._forget_network(network_id)
        self.save()

    def _forget_network(self, network_id: str) -> None:
        self._networks.pop(network_id, None)
        for key in [k for k in self._devices if k[0] == network_id]:
            self._devices.pop(key, None)
        self._dirty = True

    # ── reads ────────────────────────────────────────────────────────────

    def get(self, mac: str, network_id: str) -> DeviceRecord | None:
        with self._lock:
            return self._devices.get((network_id, _norm(mac)))

    def by_ip(self, ip: str, network_id: str) -> DeviceRecord | None:
        with self._lock:
            for (net, _mac), rec in self._devices.items():
                if net == network_id and rec.ips and rec.ips[0] == ip:
                    return rec
            return None

    def all(self, network_id: str = "") -> list[DeviceRecord]:
        with self._lock:
            records = [r for k, r in self._devices.items()
                       if not network_id or k[0] == network_id]
        return sorted(records, key=lambda r: r.last_seen, reverse=True)

    def networks(self) -> list[str]:
        with self._lock:
            return sorted(self._networks)

    def unknown(self, network_id: str) -> list[DeviceRecord]:
        """Devices on this network the user has never vouched for."""
        return [r for r in self.all(network_id) if not r.trusted]

    # ── persistence ──────────────────────────────────────────────────────

    def _evict(self, network_id: str) -> None:
        keys = [k for k in self._devices if k[0] == network_id]
        if len(keys) <= _MAX_DEVICES_PER_NETWORK:
            return
        # Drop the least recently seen, but never something the user named or
        # trusted — those are decisions, not observations.
        droppable = [k for k in keys
                     if not (self._devices[k].trusted or self._devices[k].label)]
        droppable.sort(key=lambda k: self._devices[k].last_seen)
        for key in droppable[:len(keys) - _MAX_DEVICES_PER_NETWORK]:
            self._devices.pop(key, None)

    def _maybe_save(self) -> None:
        if not self._autosave:
            return
        if time.time() - self._saved_at < _SAVE_INTERVAL:
            return
        self.save()

    def save(self) -> bool:
        with self._lock:
            if not self._dirty:
                return True
            payload = {
                "version": 1,
                "networks": self._networks,
                "labels": self._labels,
                "devices": [r.to_dict() for r in self._devices.values()],
            }
            self._dirty = False
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=1)
            os.replace(tmp, self.path)
            self._saved_at = time.time()
            return True
        except Exception as exc:
            log.warning(f"device inventory save failed: {exc}")
            with self._lock:
                self._dirty = True
            return False

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning(f"device inventory load failed: {exc}")
            return
        with self._lock:
            self._networks = dict(payload.get("networks", {}))
            self._labels = dict(payload.get("labels", {}))
            for d in payload.get("devices", []):
                rec = DeviceRecord.from_dict(d)
                if rec.mac and rec.network_id:
                    self._devices[(rec.network_id, rec.mac)] = rec
            # A network we already know is not re-learned on the next visit:
            # its baseline is exactly what was saved.
            for net in self._networks.values():
                net["learning_until"] = 0.0
            self._dirty = False
