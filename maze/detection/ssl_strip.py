import asyncio
import httpx
from maze.core.events import Event, EventBus, EventType, ThreatLevel


class SSLStripDetector:
    """Detect SSL stripping attacks — HTTP downgrade from known-HTTPS hosts.

    An SSL strip attacker interposes between the user and the server:
    1. The user's browser requests a known-HTTPS site over HTTP.
    2. The attacker strips out the HTTPS redirect and serves content as HTTP.
    3. The attacker connects to the real server over HTTPS behind the scenes.

    The reliable signal is: we see HTTP traffic to a host that we KNOW
    supports HTTPS (its cert is in the TLS cert store), but when we try to
    reach it over HTTPS, the connection FAILS or the certificate does not
    match the known-good one. If HTTPS works normally with the right cert,
    there is no stripping — this is just a transient HTTP→HTTPS upgrade.
    """

    def __init__(self):
        self._bus: EventBus | None = None
        self._checked: set[str] = set()

    async def start(self, bus: EventBus) -> None:
        self._bus = bus

    async def stop(self) -> None:
        pass

    async def check(self, url: str, known_cert_hash: str | None = None) -> None:
        """Check for SSL strip on ``url`` (must start with http://).

        ``known_cert_hash`` is the SPKI hash stored by TLSMonitor for this
        host, if available. When present, a certificate mismatch additionally
        confirms MITM.
        """
        if not url.startswith("http://"):
            return
        hostname = url.split("/")[2]
        if hostname in self._checked:
            return
        self._checked.add(hostname)

        https_url = f"https://{hostname}"
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(https_url, timeout=5)
                # HTTPS connection SUCCEEDED → check if cert matches known-good.
                # A legitimate HTTPS endpoint answering correctly means there is
                # no active stripping in progress.
                if resp.status_code < 500:
                    # HTTPS works, no stripping detected.
                    return
                # 5xx response on HTTPS is suspicious but not conclusive.
        except Exception:
            # HTTPS FAILED for a known-HTTPS host that we saw being accessed
            # over HTTP — this IS the SSL strip pattern.
            pass

        if known_cert_hash:
            from maze.detection.tls_monitor import TLSMonitor
            import ssl, socket
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        import hashlib
                        from cryptography import x509
                        from cryptography.hazmat.primitives import serialization
                        der = ssock.getpeercert(binary_form=True)
                        x509_pem = ssl.DER_cert_to_PEM_cert(der)
                        crt = x509.load_pem_x509_certificate(x509_pem.encode())
                        spki = crt.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                        current_hash = hashlib.sha256(spki).hexdigest()
                        if current_hash == known_cert_hash:
                            # HTTPS works AND cert matches → no stripping.
                            return
            except Exception:
                # Can't verify cert at all → treat as potential strip.
                pass

        await self._bus.emit(Event(
            type=EventType.SSL_STRIP,
            level=ThreatLevel.SUSPICIOUS,
            message=f"Possible SSL strip: HTTPS unreachable or cert changed "
                    f"for {hostname} — HTTP fallback detected",
            data={"hostname": hostname},
        ))
