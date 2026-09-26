"""What the rest of the Maze suite was doing when an attack landed.

An incident dossier answers "who attacked you". This answers the question the
user asks immediately afterwards: *was I covered?* Was my MAC randomised, was
DNS encrypted, was traffic going through Tor, when did anything last scan this
machine for malware. Those four answers turn a list of hostile packets into a
picture of the moment.

Two ways to learn them, in that order:

  1. ``/run/maze/status/<app>.json`` — the suite status contract. Any Maze app
     may publish a small report there; the schema is one flat object, and this
     module reads only the keys it understands. This is the direction the suite
     is moving in and costs nothing to support before every app writes one.

  2. The artefacts each app already leaves behind today — Maze Cloak's runtime
     state file, Entropy Shield's resolved drop-in, Qlam's scan history.

Rules this module holds itself to:

  * It never raises. It runs inside ``IncidentStore.record()``, on the path
    that files an attack, and a posture read failing must never cost us the
    record of the attack itself.
  * Unknown is ``None``, never ``False``. "Tor was off" and "we could not tell"
    are different claims, and only one of them is safe to put in a report that
    a user may lean on later.
  * It is cheap. Results are cached for a few seconds, because a port scan
    files many events in a burst and each one would otherwise re-stat the same
    handful of files.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

# The status contract. Not yet written by every app — read opportunistically.
STATUS_DIR = Path(os.environ.get("MAZE_STATUS_DIR", "/run/maze/status"))

# Today's real locations, used when an app publishes no status file yet.
CLOAK_STATE = Path(os.environ.get("MAZE_CLOAK_RUN", "/run/maze-cloak")) / "state.json"
DNSCRYPT_DROPIN = Path("/run/systemd/resolved.conf.d/entropy-shield.conf")
ENTROPY_RUN = Path("/run/entropy-shield")

_CACHE_TTL = 5.0
_cache: tuple[float, dict] | None = None


def _read_status(app: str) -> dict:
    """One app's published status, or {} if it publishes none."""
    try:
        with open(STATUS_DIR / f"{app}.json", "r") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _mac_randomised() -> bool | None:
    st = _read_status("maze-cloak")
    if "mac_randomised" in st:
        return bool(st["mac_randomised"])

    # Fall back to Cloak's own runtime report. Its absence is meaningful:
    # the file lives on tmpfs and the daemon removes it on shutdown, so "no
    # file" means "not running" rather than "unknown" — but only when Cloak
    # is actually installed, which we cannot tell from here. Stay honest.
    try:
        if not CLOAK_STATE.exists():
            return None
        with open(CLOAK_STATE, "r") as f:
            d = json.load(f)
    except Exception:
        return None
    if not d.get("running"):
        return False
    if d.get("paused"):
        return False
    ifaces = d.get("interfaces") or {}
    if not isinstance(ifaces, dict) or not ifaces:
        return False
    # Randomised if any interface is currently off its burned-in address.
    for st_i in ifaces.values():
        if not isinstance(st_i, dict):
            continue
        mac, orig = st_i.get("mac", ""), st_i.get("original", "")
        if mac and orig and mac.lower() != orig.lower():
            return True
        if int(st_i.get("rotations", 0) or 0) > 0:
            return True
    return False


def _entropy_shield_present() -> bool:
    """Whether Entropy Shield is on this machine at all.

    Without this check the absence of its artefacts reads as "DNS was in the
    clear", which is a claim about the user's protection rather than a fact
    about a missing file. On a machine that never had the app, the honest
    answer is that we do not know.
    """
    try:
        if ENTROPY_RUN.exists():
            return True
    except Exception:
        pass
    return shutil.which("entropy-shield") is not None


def _dns_encrypted() -> bool | None:
    st = _read_status("entropy-shield")
    if "dns_encrypted" in st:
        return bool(st["dns_encrypted"])
    try:
        if DNSCRYPT_DROPIN.exists():
            return True
    except Exception:
        return None
    return False if _entropy_shield_present() else None


def _tor_proxy() -> bool | None:
    st = _read_status("entropy-shield")
    if "tor_proxy" in st:
        return bool(st["tor_proxy"])
    # Entropy Shield builds its Tor state under its runtime directory only
    # while the transparent proxy is up.
    try:
        if ENTROPY_RUN.is_dir():
            return (ENTROPY_RUN / "tor-data").is_dir()
    except Exception:
        return None
    return False if _entropy_shield_present() else None


def _last_av_scan() -> float | None:
    """Unix time of the most recent Qlam scan, or None if never / unknown."""
    st = _read_status("qlam")
    if "last_scan" in st:
        try:
            return float(st["last_scan"])
        except (TypeError, ValueError):
            return None
    try:
        hist = Path.home() / ".local" / "share" / "Qlam" / "history.json"
        with open(hist, "r") as f:
            data = json.load(f)
    except Exception:
        return None
    entries = data if isinstance(data, list) else data.get("scans", [])
    newest = None
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        for key in ("timestamp", "ts", "date", "finished_at"):
            v = e.get(key)
            if v is None:
                continue
            try:
                t = float(v)
            except (TypeError, ValueError):
                continue
            newest = t if newest is None else max(newest, t)
            break
    return newest


def capture(force: bool = False) -> dict:
    """The suite's defensive posture right now.

    Every value is True, False, or None for "could not tell". Callers store
    this verbatim alongside an incident, so the keys are stable.
    """
    global _cache
    now = time.time()
    if not force and _cache is not None and (now - _cache[0]) < _CACHE_TTL:
        return dict(_cache[1])

    try:
        snap = {
            "at": now,
            "mac_randomised": _mac_randomised(),
            "dns_encrypted": _dns_encrypted(),
            "tor_proxy": _tor_proxy(),
            "last_av_scan": _last_av_scan(),
        }
    except Exception:
        # Belt and braces: capture() is called while filing an attack.
        snap = {"at": now, "mac_randomised": None, "dns_encrypted": None,
                "tor_proxy": None, "last_av_scan": None}

    _cache = (now, snap)
    return dict(snap)


def describe(snap: dict) -> list[str]:
    """Human lines for a report. Skips anything we could not determine."""
    if not snap:
        return []
    out: list[str] = []
    mapping = (
        ("mac_randomised", "MAC address randomised", "MAC address was the hardware one"),
        ("dns_encrypted", "DNS encrypted (DNSCrypt)", "DNS was in the clear"),
        ("tor_proxy", "traffic through Tor", "traffic was not going through Tor"),
    )
    for key, yes, no in mapping:
        v = snap.get(key)
        if v is True:
            out.append(yes)
        elif v is False:
            out.append(no)
    last = snap.get("last_av_scan")
    if last:
        days = (time.time() - float(last)) / 86400.0
        if days < 1:
            out.append("malware scan ran today")
        else:
            out.append(f"last malware scan {int(days)} day(s) before")
    return out
