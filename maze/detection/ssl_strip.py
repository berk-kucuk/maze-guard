"""
HTTPS downgrade detection.

The previous implementation could not fire. It was reachable only through the
engine's monitor loop, which asked for the *reverse DNS* of every host we had
an open port-80 connection to and compared it against the two TLS canary
hostnames ("cloudflare.com", "github.com"). No production IP's PTR record
answers with either name, so the comparison never matched and the module spent
its life reporting Active while running no check at all.

What replaces it works from evidence we genuinely have. Without payload access
we cannot see an attacker rewriting https:// links inside a page, so this does
not pretend to. What it *can* establish, from connection metadata alone:

  1. This remote address served us TLS on 443 — we watched a socket to it.
  2. We are now talking to that same address in the clear, on port 80.
  3. Its 443 no longer answers, or no longer completes a TLS handshake.

Together those three are a downgrade: something is keeping the encrypted path
shut so traffic has to fall back to plaintext, which is the position an
on-path attacker needs before anything else. Point 3 is what keeps this quiet
in normal use — every ordinary web server is reachable on both ports, and a
host that answers TLS fine is never reported no matter how much plain HTTP we
send it.

Certificate *substitution* — the other half of an interception attack — is not
this module's job; TLSMonitor pins the public key and reports a swap.
"""
import asyncio
import ipaddress
import socket
import ssl
import time

from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import FAIL, INFO, PASS, Verdict
from maze.utils.logger import log

# How long an address stays on the "this host speaks TLS" list without being
# seen again. Long enough to span a browsing session, short enough that an
# address reassigned to something else does not haunt us for the whole run.
_TLS_MEMORY = 6 * 3600.0
# Don't re-probe the same address more often than this.
_RECHECK_AFTER = 900.0
# An alert about one address is not repeated inside this window.
_REALERT_AFTER = 3600.0
# Bound the endpoint table on a busy machine.
_MAX_ENDPOINTS = 2048
# A failed handshake has to be confirmed before it is reported: 443 can fail
# once for entirely local reasons (a link flap, a suspended laptop).
_CONFIRMATIONS = 2


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class SSLStripDetector:
    def __init__(self):
        self._bus: EventBus | None = None
        self._tls_hosts: dict[str, float] = {}     # ip -> last seen on 443
        self._probed: dict[str, float] = {}        # ip -> last probe
        self._failures: dict[str, int] = {}        # ip -> consecutive failures
        self._alerted: dict[str, float] = {}       # ip -> last alert

    async def start(self, bus: EventBus) -> None:
        self._bus = bus

    async def stop(self) -> None:
        pass

    # ── what the interface shows ─────────────────────────────────────────

    def status_detail(self) -> str:
        n = len(self._tls_hosts)
        if not n:
            return "no TLS endpoint seen yet — nothing to compare against"
        return f"watching {n} endpoint{'s' if n != 1 else ''} known to serve TLS"

    # ── self-test ────────────────────────────────────────────────────────

    async def verify(self) -> Verdict:
        """Exercise the probe this detector's entire verdict rests on.

        The question it asks of the network is "does 443 still complete a TLS
        handshake". If that probe cannot run — no outbound 443, a proxy in the
        way — the detector can never report anything, and would otherwise stay
        silent in a way indistinguishable from "all clear".
        """
        target, source = "", ""
        if self._tls_hosts:
            target = max(self._tls_hosts, key=self._tls_hosts.get)
            source = "an endpoint this machine has been talking to"
        else:
            # Nothing observed yet — use a canary so the probe is still proven.
            import socket as _socket
            try:
                target = await asyncio.to_thread(
                    _socket.gethostbyname, "cloudflare.com")
                source = "cloudflare.com, as no endpoint has been seen yet"
            except Exception as exc:
                return Verdict(FAIL,
                               f"the TLS probe cannot be tested: no address to "
                               f"probe and no DNS to find one — {exc}")

        reachable = await asyncio.to_thread(self._tls_reachable, target)
        evidence = [f"probed {target} ({source})",
                    f"{len(self._tls_hosts)} endpoints known to serve TLS"]
        if not reachable:
            return Verdict(FAIL,
                           f"a TLS handshake with {target}:443 did not "
                           f"complete — either the probe cannot reach the "
                           f"network, or the encrypted path really is being "
                           f"suppressed", evidence)
        if not self._tls_hosts:
            return Verdict(INFO,
                           "the downgrade probe works, but no TLS endpoint has "
                           "been observed yet — there is nothing to watch until "
                           "this machine visits an HTTPS site", evidence)
        return Verdict(PASS,
                       f"the downgrade probe works and {len(self._tls_hosts)} "
                       f"endpoints are being watched for a dead 443", evidence)

    # ── evidence intake ──────────────────────────────────────────────────

    def note_tls_endpoint(self, ip: str) -> None:
        """Record that ``ip`` served us TLS. Called for every live :443 socket."""
        if not ip:
            return
        now = time.monotonic()
        self._tls_hosts[ip] = now
        if len(self._tls_hosts) > _MAX_ENDPOINTS:
            self._prune(now)

    def knows_tls(self, ip: str) -> bool:
        entry = self._tls_hosts.get(ip)
        if entry is None:
            return False
        if time.monotonic() - entry > _TLS_MEMORY:
            self._tls_hosts.pop(ip, None)
            return False
        return True

    def _prune(self, now: float) -> None:
        for ip, seen in list(self._tls_hosts.items()):
            if now - seen > _TLS_MEMORY:
                del self._tls_hosts[ip]
        # Still oversized (a scan-like burst of endpoints): drop the oldest.
        if len(self._tls_hosts) > _MAX_ENDPOINTS:
            for ip, _ in sorted(self._tls_hosts.items(),
                                key=lambda kv: kv[1])[:len(self._tls_hosts)
                                                      - _MAX_ENDPOINTS]:
                del self._tls_hosts[ip]

    # ── the check ────────────────────────────────────────────────────────

    async def check_downgrade(self, ip: str, hostname: str = "") -> None:
        """Report ``ip`` if it is being used in the clear while its TLS port is
        no longer reachable. Silent unless all three conditions hold."""
        if not ip or not self.knows_tls(ip):
            return
        now = time.monotonic()
        if now - self._probed.get(ip, -_RECHECK_AFTER) < _RECHECK_AFTER:
            return
        self._probed[ip] = now

        if await asyncio.to_thread(self._tls_reachable, ip, hostname):
            # The encrypted path is fine, so plaintext traffic to the same host
            # is just an ordinary HTTP request (a redirect, OCSP, a captive
            # portal check). Not a downgrade, and not worth a word.
            self._failures.pop(ip, None)
            self._tls_hosts[ip] = now
            return

        fails = self._failures.get(ip, 0) + 1
        self._failures[ip] = fails
        if fails < _CONFIRMATIONS:
            # Give a transient failure the chance to be transient. Probe again
            # on the next pass rather than sitting on the cooldown.
            self._probed[ip] = now - _RECHECK_AFTER + 60
            return
        if now - self._alerted.get(ip, -_REALERT_AFTER) < _REALERT_AFTER:
            return
        self._alerted[ip] = now
        self._failures.pop(ip, None)

        where = f"{hostname} ({ip})" if hostname else ip
        await self._bus.emit(Event(
            type=EventType.SSL_STRIP,
            level=ThreatLevel.DANGEROUS,
            message=(f"HTTPS downgrade: {where} served us TLS earlier, but its "
                     f"port 443 no longer answers while traffic keeps flowing "
                     f"to it in plaintext on port 80 — the encrypted path is "
                     f"being suppressed"),
            data={"ip": ip, "src": ip, "hostname": hostname,
                  "technique": "https_downgrade"},
        ))

    async def check(self, url: str, known_cert_hash: str | None = None) -> None:
        """Hostname-shaped entry point: ``check("http://example.com")``.

        Kept because a hostname is what the user-facing tooling has to hand.
        It resolves to an address and defers to the same evidence-based test,
        so there is exactly one code path that can raise this alert.
        """
        if not url.startswith("http://"):
            return
        hostname = url.split("/", 3)[2].split(":")[0]
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, hostname)
        except Exception as exc:
            log.debug(f"SSLStripDetector: cannot resolve {hostname} — {exc}")
            return
        # A hostname the caller cares about is worth trusting as a TLS endpoint
        # even if we never watched a socket to it.
        self.note_tls_endpoint(ip)
        await self.check_downgrade(ip, hostname)

    @staticmethod
    def _tls_reachable(ip: str, server_name: str = "") -> bool:
        """Whether ``ip``:443 still speaks TLS.

        Certificate validation is deliberately off: we are asking "is the
        encrypted port still there", not "is the certificate the right one" —
        the address may legitimately host many names, and none of them is known
        here. Who the certificate belongs to is TLSMonitor's question.

        Any TLS answer counts, including a handshake *alert*. CDNs refuse a
        ClientHello without SNI (or with a name they do not serve) by sending
        an alert — the probe used to read that as "443 is dead" and reported a
        downgrade for half the web. The port is dead only when nothing answers:
        refused, timed out, or cut before the server said anything.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sni = server_name if server_name and not _is_ip(server_name) else None
        try:
            sock = socket.create_connection((ip, 443), timeout=6)
        except OSError:
            return False
        try:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True
        except ssl.SSLError as exc:
            # A TLS record came back (an alert, a protocol version we will not
            # speak): the encrypted path exists. EOF with no bytes is a reset
            # by whoever sits in the middle, which is the stripping signature.
            return not isinstance(exc, ssl.SSLEOFError)
        except OSError:
            return False
        finally:
            sock.close()
