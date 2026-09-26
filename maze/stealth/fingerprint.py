"""
Make this host's TCP/IP stack less identifiable.

Passive fingerprinting reads the parts of a packet nobody chose deliberately:
the initial TTL says which family of operating system sent it, and the TCP
timestamp option carries a clock that reveals system uptime and lets separate
connections be tied to one machine. Normalising those makes a Linux desktop
look like the most common thing on any network instead of like itself.

Two changes from the earlier version:

* ``net.ipv4.tcp_window_scaling=0`` was being switched off. Window scaling is
  what allows a TCP connection to use more than 64 KB in flight; disabling it
  collapses throughput on any fast or long-distance link, which is a real cost
  paid for a fingerprinting bit that scanners barely weigh. It is replaced by
  ``tcp_timestamps``, which leaks considerably more and costs nothing.
* The original values are written to disk. They used to live only in memory, so
  a crash — or a helper that dropped before ``stop()`` — left the machine
  permanently retuned with nothing recording what it had been.
"""
import json
from pathlib import Path

from maze.core.verify import FAIL, PASS, Verdict, WARN
from maze.utils.logger import log

# Kept in the user's own config directory rather than a predictable /tmp path:
# a world-writable location lets another local user pre-create the file and
# dictate what gets written back to sysctl when this module stops.
_STATE_FILE = Path.home() / ".config" / "maze" / "fingerprint-state"

# These keys must also appear in helper.py's _SYSCTL_ALLOWED, or the daemon
# refuses them. A helper older than this module simply rejects the ones it does
# not know, so the rest are still applied.
_SYSCTL_RULES = [
    # 128 is the Windows default and by far the most common initial TTL on a
    # public network — the point is to be unremarkable, not to be invisible.
    ("net.ipv4.ip_default_ttl", "128"),
    ("net.ipv6.conf.all.hop_limit", "128"),
    # Removes the timestamp option: no uptime, and no clock to correlate this
    # machine's connections by.
    ("net.ipv4.tcp_timestamps", "0"),
]


class FingerprintProtector:
    def __init__(self):
        self._original: dict[str, str] = {}
        self._applied: dict[str, str] = {}
        self._helper = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, bus, helper=None) -> None:
        self._helper = helper
        if not (helper and helper.is_connected()):
            raise PermissionError(
                "the privileged helper is not connected, so kernel tuning "
                "cannot be applied")

        # A state file left behind means a previous run never got to restore.
        # Those recorded values are the true originals; what sysctl reports now
        # is this module's own handiwork, so it must not be mistaken for one.
        stale = self._load_state()
        self._original = dict(stale)
        self._applied = {}

        # Read everything first. Nothing is written until the originals are on
        # disk: a crash between the change and the record is the one ordering
        # that loses what this machine looked like before Maze Guard touched
        # it, and it is not recoverable afterwards.
        readable: dict[str, tuple[str, str]] = {}
        unavailable: list[str] = []
        for key, target in _SYSCTL_RULES:
            current = await helper.sysctl_get(key)
            if current is None:
                # Either the key does not exist on this kernel or the running
                # daemon predates it. Neither is fatal on its own.
                unavailable.append(key)
                continue
            readable[key] = (current, target)
            self._original.setdefault(key, current)

        if not self._original:
            raise RuntimeError(
                "could not read any fingerprint setting through the helper "
                "(it may be busy, restarting, or older than this build) — "
                "details: journalctl -u maze-guard.service -e")
        self._save_state()
        if unavailable:
            log.warning("FingerprintProtector: not available on this system — "
                        + ", ".join(unavailable))

        refused = []
        for key, (current, target) in readable.items():
            if current == target:
                # Already where we want it. Not a failure and not a no-op
                # either: the value is masked, which is the entire point. This
                # branch used to fall through to an error that claimed the
                # kernel had accepted nothing, so a machine that was ALREADY
                # protected was the one case reported as broken.
                continue
            if await helper.sysctl_set(key, target):
                self._applied[key] = target
                log.info(f"FingerprintProtector: set {key}={target} "
                         f"(was {self._original[key]})")
            else:
                refused.append(f"{key} (kernel refused {target})")

        needed = [k for k, (c, t) in readable.items() if c != t]
        if needed and not self._applied:
            raise RuntimeError(
                "the kernel refused every fingerprint setting: "
                + ", ".join(refused))
        if refused:
            log.warning("FingerprintProtector: " + ", ".join(refused))

    async def stop(self) -> None:
        if self._helper and self._helper.is_connected():
            for key, original in self._original.items():
                await self._helper.sysctl_set(key, original)
            log.info("FingerprintProtector: sysctl values restored")
            _STATE_FILE.unlink(missing_ok=True)
        else:
            # Nothing can be restored without the helper. Leave the state file
            # in place so the next run — or a user reading it — still knows
            # what these values were before Maze Guard touched them.
            log.warning("FingerprintProtector: helper gone, kernel settings "
                        f"left as they are; originals recorded in {_STATE_FILE}")
        self._original = {}
        self._applied = {}

    # ── what the interface shows ─────────────────────────────────────────

    def status_detail(self) -> str:
        if not self._applied:
            return ("the kernel already held every masked value — nothing "
                    "needed changing")
        return ", ".join(f"{k.rsplit('.', 1)[-1]}={v}"
                         for k, v in sorted(self._applied.items()))

    # ── self-test ────────────────────────────────────────────────────────

    async def verify(self) -> Verdict:
        """Read the values back out of the kernel.

        What this module *set* and what the kernel *holds* are different facts:
        a sysctl the daemon refused, a key that does not exist on this kernel,
        or anything else on the system writing the same knob afterwards all
        make the second one the only one worth reporting.
        """
        if not (self._helper and self._helper.is_connected()):
            return Verdict(FAIL,
                           "the privileged helper is not connected, so the "
                           "kernel cannot be asked what it is set to")
        matched, wrong, absent = [], [], []
        for key, target in _SYSCTL_RULES:
            current = await self._helper.sysctl_get(key)
            if current is None:
                absent.append(key)
            elif current == target:
                matched.append(f"{key} = {current}")
            else:
                wrong.append(f"{key} = {current} (unmasked; want {target})")
        if wrong or not matched:
            return Verdict(FAIL,
                           "this host's stack is still identifiable: the "
                           "kernel is not holding the masked values",
                           matched + wrong
                           + [f"{k}: not available on this kernel or daemon"
                              for k in absent])
        if absent:
            return Verdict(WARN,
                           f"{len(matched)} of {len(_SYSCTL_RULES)} values are "
                           f"masked; the rest are unavailable here",
                           matched + [f"{k}: not available on this kernel or "
                                      f"daemon" for k in absent])
        return Verdict(PASS,
                       "the kernel reports the masked values: TTL and hop "
                       "limit normalised, TCP timestamps off (no uptime leak)",
                       matched)

    # ── state file ───────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, str]:
        try:
            data = json.loads(_STATE_FILE.read_text())
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        allowed = {k for k, _ in _SYSCTL_RULES}
        return {k: str(v) for k, v in data.items()
                if k in allowed and str(v).isdigit()}

    def _save_state(self) -> None:
        try:
            _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _STATE_FILE.write_text(json.dumps(self._original, indent=2))
        except Exception as exc:
            log.warning(f"FingerprintProtector: could not record originals: {exc}")
