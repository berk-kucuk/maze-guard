"""
What happened *after* we blocked something.

Every rule Maze Guard installs carries a `log prefix=MAZE-BLOCK` clause, so the
kernel records each packet the drop rule swallows. Until now nobody read those
lines back, which meant the dossier ended at "blocked" — the least interesting
moment. Whether a host accepted the block or kept hammering for an hour is the
difference between a misconfigured printer and someone working at it, and the
kernel already knows the answer.

Read-only and unprivileged: `journalctl -k` is readable by members of the
`wheel`, `adm` or `systemd-journal` groups on a normal system, and where it is
not, this degrades to "unavailable" rather than reaching for root.
"""
import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from maze.utils.logger import log

# Kernel log lines look like:
#   MAZE-BLOCKIN=enp42s0 OUT= MAC=01:00:5e:… SRC=192.168.0.28 DST=224.0.0.251
#   LEN=472 … PROTO=UDP SPT=5353 DPT=5353 LEN=452
# The prefix runs straight into IN= because firewalld does not add a separator,
# which is why nothing here anchors on a space after it.
_FIELD_RE = re.compile(
    r'SRC=(?P<src>\S+).*?DST=(?P<dst>\S+)'
    r'(?:.*?PROTO=(?P<proto>\S+))?(?:.*?DPT=(?P<dpt>\d+))?')
_TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

_MAX_PORTS_RECORDED = 40


@dataclass
class BlockedTraffic:
    """Everything one source sent us while its block was in force."""
    src: str
    packets: int = 0
    ports: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    first: datetime | None = None
    last: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "src": self.src, "packets": self.packets,
            "ports": sorted(self.ports)[:_MAX_PORTS_RECORDED],
            "protocols": sorted(self.protocols),
            "first": self.first.isoformat() if self.first else "",
            "last": self.last.isoformat() if self.last else "",
        }


def parse(lines, after: datetime | None = None) -> dict[str, BlockedTraffic]:
    """Fold raw journal lines into one record per source address.

    ``after`` drops anything at or before that instant. Callers poll with a
    watermark and journalctl's --since is inclusive to the second, so without
    this the packets logged in the boundary second would be counted twice.
    """
    out: dict[str, BlockedTraffic] = {}
    for line in lines:
        if "MAZE-" not in line:
            continue
        ts = _timestamp(line)
        if after is not None and (ts is None or ts <= after):
            continue
        m = _FIELD_RE.search(line)
        if not m:
            continue
        src = m.group("src")
        rec = out.get(src)
        if rec is None:
            rec = out[src] = BlockedTraffic(src=src)
        rec.packets += 1
        if m.group("proto"):
            rec.protocols.add(m.group("proto"))
        if m.group("dpt") and len(rec.ports) < _MAX_PORTS_RECORDED:
            try:
                rec.ports.add(int(m.group("dpt")))
            except ValueError:
                pass
        if ts:
            rec.first = min(rec.first or ts, ts)
            rec.last = max(rec.last or ts, ts)
    return out


def _timestamp(line: str) -> datetime | None:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1))
    except ValueError:
        return None


def read_sync(since: str = "-1h", limit: int = 20000,
              after: datetime | None = None) -> dict[str, BlockedTraffic]:
    """Read the kernel log for our own drop-rule hits.

    `since` is passed to journalctl verbatim ("-1h", "2026-08-22 21:00:00").
    Returns {} when the journal cannot be read — an empty result and an
    unreadable journal are deliberately not distinguished here; the caller
    that needs to know asks :func:`available`.
    """
    try:
        proc = subprocess.run(
            ["journalctl", "-k", "--no-pager", "-o", "short-iso",
             "--since", since, "--grep", "MAZE-", "-n", str(limit)],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as exc:
        log.debug(f"block log unavailable: {exc}")
        return {}
    if proc.returncode != 0:
        log.debug(f"block log unavailable (rc={proc.returncode}): "
                  f"{proc.stderr.strip()[:120]}")
        return {}
    return parse(proc.stdout.splitlines(), after=after)


async def read(since: str = "-1h", limit: int = 20000,
               after: datetime | None = None) -> dict[str, BlockedTraffic]:
    return await asyncio.to_thread(read_sync, since, limit, after)


def available() -> bool:
    """Whether this user can read the kernel journal at all."""
    try:
        proc = subprocess.run(["journalctl", "-k", "-n", "1", "--no-pager"],
                              capture_output=True, text=True, timeout=5)
        return proc.returncode == 0
    except Exception:
        return False
