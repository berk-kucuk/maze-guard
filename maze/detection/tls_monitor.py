import asyncio
import hashlib
import time
import ssl
import socket
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import FAIL, PASS, Verdict, WARN
from maze.utils.logger import log

_CONFIRMATIONS = 2    # consecutive untrusted answers before alerting
_CLOCK_FLOOR = 1767225600   # 2026-01-01T00:00:00Z

# Hosts whose TLS certificates are checked as MITM canaries. An interceptor
# has to present its own certificate for them, and short of a compromised CA
# (or a root the user installed) that certificate does not verify — so the
# signal is an untrusted chain, not a changed key. Keys change at renewal and
# differ between CDN edges; the SPKI is recorded for the evidence only.
_CANARY_HOSTS = ["cloudflare.com", "github.com"]


class TLSMonitor:
    def __init__(self):
        self._spki_store: dict[str, str] = {}
        self._pending: dict[str, tuple[str, int]] = {}  # host -> (hash, count)
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._env_broken = False      # a dependency this cannot work without
        self._reachable = False       # at least one canary answered

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def verify(self) -> Verdict:
        """Fetch each canary certificate now and say what the wire shows.

        The question is whether this machine can still reach the canaries over
        TLS it can *trust*. An interceptor cannot present a certificate that a
        public CA signed for github.com, so an untrusted chain on a canary is
        the finding; a different key under a valid chain is an ordinary renewal.
        """
        results, intercepted = [], []
        for host in _CANARY_HOSTS:
            probe = await asyncio.to_thread(self._probe, host, 443)
            if probe is None:
                results.append(f"{host}: unreachable")
            elif probe.trusted:
                self._spki_store[host] = probe.spki
                results.append(f"{host}: trusted chain, spki={probe.spki[:16]}…")
            elif probe.clock_problem:
                results.append(f"{host}: certificate rejected because of the "
                               f"system clock — {probe.reason}")
            else:
                intercepted.append(f"{host}: untrusted certificate "
                                   f"(issuer: {probe.issuer or 'unknown'}) — "
                                   f"{probe.reason}")
        if self._env_broken:
            return Verdict(FAIL,
                           "the 'cryptography' package is missing, so no "
                           "certificate can be read — this detector cannot "
                           "work on this machine", results)
        if intercepted:
            return Verdict(FAIL,
                           "HTTPS from this machine is being intercepted: a "
                           "canary answered with a certificate no trusted CA "
                           "signed", intercepted + results)
        if not self._spki_store:
            return Verdict(WARN,
                           "no canary could be reached, so nothing could be "
                           "checked", results)
        return Verdict(PASS,
                       f"live check against {len(self._spki_store)} canaries: "
                       f"every one presented a trusted certificate", results)

    def status_detail(self) -> str:
        if self._env_broken:
            return ("the 'cryptography' package is missing — no certificate "
                    "can be read, so nothing is being compared")
        if not self._spki_store:
            return "no canary certificate fetched yet — no baseline to compare"
        return (f"{len(self._spki_store)} of {len(_CANARY_HOSTS)} canaries "
                f"pinned: " + ", ".join(sorted(self._spki_store)))

    async def _monitor(self) -> None:
        for host in _CANARY_HOSTS:
            probe = await asyncio.to_thread(self._probe, host, 443)
            if probe is not None and probe.trusted:
                self._spki_store[host] = probe.spki
        if not self._spki_store and not self._env_broken:
            log.warning("TLSMonitor: no canary certificate could be fetched — "
                        "MITM detection has no baseline to compare against")
        while True:
            await asyncio.sleep(300)
            for host in _CANARY_HOSTS:
                try:
                    await self.check(host)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # never let one bad fetch end the loop
                    log.warning(f"TLSMonitor: check of {host} failed — {exc}")

    async def check(self, hostname: str, port: int = 443) -> None:
        """One canary, one verdict.

        This used to be inverted. It fetched the certificate over a *verified*
        connection, so a real interceptor — whose certificate fails
        verification — made the fetch fail and the check return in silence,
        while a canary's ordinary key rotation at renewal was reported as
        "possible MITM". Now a trusted chain is simply re-pinned, and an
        untrusted one is the alert.
        """
        probe = await asyncio.to_thread(self._probe, hostname, port)
        if probe is None:
            return                          # unreachable says nothing
        if probe.trusted:
            self._pending.pop(hostname, None)
            known = self._spki_store.get(hostname)
            if known and known != probe.spki:
                log.info(f"TLSMonitor: {hostname} rotated its key under a "
                         f"valid chain — re-pinned")
            self._spki_store[hostname] = probe.spki
            return
        if probe.clock_problem:
            # Every certificate looks expired to a machine whose clock is off.
            # That breaks HTTPS, but nobody is intercepting anything.
            log.warning(f"TLSMonitor: {hostname} rejected for validity dates "
                        f"— check the system clock ({probe.reason})")
            return
        _digest, count = self._pending.get(hostname, ("", 0))
        count += 1
        if count < _CONFIRMATIONS:
            self._pending[hostname] = (probe.spki, count)
            return
        self._pending.pop(hostname, None)
        if self._bus:
            await self._bus.emit(Event(
                type=EventType.TLS_CHANGE,
                level=ThreatLevel.SUSPICIOUS,
                message=(f"HTTPS to {hostname} is intercepted: the certificate "
                         f"is not trusted (issuer: {probe.issuer or 'unknown'}). "
                         f"A captive portal does this before you log in; "
                         f"anywhere else it means someone is reading HTTPS "
                         f"traffic"),
                data={"hostname": hostname, "issuer": probe.issuer,
                      "reason": probe.reason, "spki": probe.spki,
                      "pinned": self._spki_store.get(hostname, "")},
            ))

    def _probe(self, hostname: str, port: int) -> "_Probe | None":
        """Handshake with ``hostname`` and describe the certificate.

        None when the host cannot be reached at all, or when the
        `cryptography` package is missing — the latter reported once, loudly,
        because it leaves the detector permanently blind.
        """
        try:
            import cryptography.x509  # noqa: F401
        except ImportError as exc:
            if not self._env_broken:
                self._env_broken = True
                log.error(f"TLSMonitor is inoperative: {exc}. "
                          f"Install the 'cryptography' package.")
            return None
        try:
            der = self._fetch_der(hostname, port, verify=True)
            if der is None:
                return None
            self._reachable = True
            return _Probe(True, _spki_digest(der), _issuer(der), "")
        except ssl.SSLCertVerificationError as exc:
            reason = exc.verify_message or str(exc)
        except Exception as exc:
            log.debug(f"TLSMonitor: {hostname}:{port} unreachable — {exc}")
            return None
        # The verified handshake was refused over the certificate itself: read
        # it again without verification, to say who issued it.
        try:
            der = self._fetch_der(hostname, port, verify=False)
        except Exception:
            der = None
        self._reachable = True
        return _Probe(False, _spki_digest(der) if der else "",
                      _issuer(der) if der else "", reason)

    @staticmethod
    def _fetch_der(hostname: str, port: int, verify: bool) -> bytes | None:
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True) or None


class _Probe:
    __slots__ = ("trusted", "spki", "issuer", "reason")

    def __init__(self, trusted: bool, spki: str, issuer: str, reason: str):
        self.trusted, self.spki, self.issuer, self.reason = \
            trusted, spki, issuer, reason

    @property
    def clock_problem(self) -> bool:
        """A date rejection on a machine whose clock is plainly wrong.

        Only then: an interceptor can just as well present an expired
        certificate, so the dates alone must not buy silence. A clock that
        reads earlier than this code was written has been reset (dead RTC
        battery, fresh VM), and then every certificate looks invalid.
        """
        text = self.reason.lower()
        dated = "expired" in text or "not yet valid" in text
        return dated and time.time() < _CLOCK_FLOOR


def _load(der: bytes):
    import cryptography.x509
    return cryptography.x509.load_der_x509_certificate(der)


def _spki_digest(der: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    spki = _load(der).public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _issuer(der: bytes) -> str:
    try:
        return _load(der).issuer.rfc4514_string()[:120]
    except Exception:
        return ""
