import asyncio
import hashlib
import ssl
import socket
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log

_SETTLING_CHECKS = 3  # must persist across this many checks before alerting

# Hosts whose TLS certs are monitored as MITM canaries.
# If the Subject Public Key Info (SPKI) hash changes between checks, someone
# is intercepting HTTPS. Pinning the SPKI (public key) is more reliable than
# the full certificate: certificate renewal/changes the DER hash but NOT the
# public key that secured the connection. Only a true MITM or complete server
# key rotation changes the SPKI.
# google.com is excluded: its massive CDN rotates leaf-cert keys frequently and
# serves different keys from different edge nodes, producing false positives.
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

    async def _monitor(self) -> None:
        for host in _CANARY_HOSTS:
            h = await asyncio.to_thread(self._get_spki_hash, host, 443)
            if h:
                self._spki_store[host] = h
        if not self._spki_store and not self._env_broken:
            log.warning("TLSMonitor: no canary certificate could be fetched — "
                        "MITM detection has no baseline to compare against")
        while True:
            await asyncio.sleep(300)
            for host in _CANARY_HOSTS:
                await self.check(host)

    async def check(self, hostname: str, port: int = 443) -> None:
        cert_hash = await asyncio.to_thread(self._get_spki_hash, hostname, port)
        if cert_hash is None:
            return
        known = self._spki_store.get(hostname)
        if known and known != cert_hash:
            pending = self._pending.get(hostname, (None, 0))
            if pending[0] == cert_hash:
                count = pending[1] + 1
                if count >= _SETTLING_CHECKS:
                    del self._pending[hostname]
                    await self._bus.emit(Event(
                        type=EventType.TLS_CHANGE,
                        level=ThreatLevel.SUSPICIOUS,
                        message=f"TLS public key changed for {hostname} — possible MITM",
                        data={"hostname": hostname, "old": known, "new": cert_hash},
                    ))
                    self._spki_store[hostname] = cert_hash
                    return
                else:
                    self._pending[hostname] = (cert_hash, count)
                    return
            else:
                self._pending[hostname] = (cert_hash, 1)
                return
        self._pending.pop(hostname, None)
        if known and known == cert_hash:
            return
        self._spki_store[hostname] = cert_hash

    def _get_spki_hash(self, hostname: str, port: int) -> str | None:
        """SHA-256 of the Subject Public Key Info, or None if it cannot be read.

        The two ways this returns None are not the same thing, and conflating
        them hid a dead module: an unreachable host is expected and temporary,
        while a missing `cryptography` package means this detector can never
        work — yet both used to return None in silence, leaving the interface
        showing TLS Monitor as Active while it checked nothing. Environment
        failures are now reported once, loudly.
        """
        try:
            import cryptography.x509
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:
            if not self._env_broken:
                self._env_broken = True
                log.error(f"TLSMonitor is inoperative: {exc}. "
                          f"Install the 'cryptography' package.")
            return None

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if not der:
                        return None
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    crt = cryptography.x509.load_pem_x509_certificate(pem.encode())
                    spki = crt.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    self._reachable = True
                    return hashlib.sha256(spki).hexdigest()
        except Exception as exc:
            log.debug(f"TLSMonitor: {hostname}:{port} unreachable — {exc}")
            return None
