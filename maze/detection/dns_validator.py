import asyncio
import socket
import httpx
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log

# JSON DoH endpoints, one per independent operator.
#
# These URLs are not interchangeable with the RFC 8484 wire-format ones, and
# getting them wrong fails quietly: `/dns-query` on Google serves an HTML page
# and Quad9 answers "unable to decode BASE64-URL", both of which blew up in
# resp.json() and were swallowed as "resolver unreachable". With two of the
# three silently out, the code never had the two agreeing answers it requires
# and returned "looks fine" for every domain — DNS poisoning detection was
# switched on in the interface and doing nothing at all.
DOH_RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/resolve",
    "adguard":    "https://dns.adguard-dns.com/resolve",
}

# Canary domains chosen because they resolve to a small, globally-stable set of
# anycast IPs — unlike CDN-fronted sites (google.com, etc.) whose A records vary
# per resolver and per edge, which made naive resolver-vs-resolver comparison
# fire constantly. With stable IPs we can compare the *local* system resolver
# (which an on-path attacker can poison via rogue DHCP/DNS) against the DoH
# consensus (fetched over HTTPS, hard to tamper with). A mismatch is a real
# signal of local DNS poisoning rather than benign CDN load-balancing.
_CANARY_DOMAINS = ["one.one.one.one", "dns.google", "dns.quad9.net"]


class DNSValidator:
    def __init__(self):
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._warned: set[str] = set()

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _monitor(self) -> None:
        await asyncio.sleep(30)  # let network settle before first check
        while True:
            for domain in _CANARY_DOMAINS:
                try:
                    await self.validate(domain)
                except Exception:
                    pass
            await asyncio.sleep(120)

    async def validate(self, domain: str) -> bool:
        """Return False (and emit) if the local resolver disagrees with the
        DoH consensus for `domain`, indicating possible DNS poisoning."""
        doh_results = await asyncio.gather(*[
            self._doh_resolve(url, domain)
            for url in DOH_RESOLVERS.values()
        ], return_exceptions=True)

        # Trusted baseline = union of what the DoH resolvers returned.
        trusted: set[str] = set()
        agreeing = 0
        for r in doh_results:
            if isinstance(r, set) and r:
                trusted |= r
                agreeing += 1
        # Need at least two independent DoH answers to trust the baseline.
        if agreeing < 2 or not trusted:
            # Say so once. Silently returning "fine" here is how this detector
            # spent its life reporting Active while validating nothing.
            if "__baseline__" not in self._warned:
                self._warned.add("__baseline__")
                reasons = [str(r) for r in doh_results if isinstance(r, Exception)]
                log.warning(
                    f"DNSValidator: only {agreeing} of {len(DOH_RESOLVERS)} "
                    f"DoH resolvers answered — cannot validate DNS until at "
                    f"least two are reachable"
                    + (f" ({reasons[0]})" if reasons else ""))
                if self._bus:
                    await self._bus.emit(Event(
                        type=EventType.DNS_SPOOF,
                        level=ThreatLevel.SUSPICIOUS,
                        message="DNS validation unavailable: fewer than two "
                                "trusted resolvers are reachable, so local DNS "
                                "answers cannot be cross-checked",
                        data={"agreeing": agreeing,
                              "resolvers": list(DOH_RESOLVERS)},
                    ))
            return True
        # Recovered — allow the warning again if it breaks a second time.
        self._warned.discard("__baseline__")

        local = await self._local_resolve(domain)
        if not local:
            return True

        # Any locally-resolved IP absent from the trusted set is suspicious.
        rogue = local - trusted
        if rogue and domain not in self._warned:
            self._warned.add(domain)
            await self._bus.emit(Event(
                type=EventType.DNS_SPOOF,
                level=ThreatLevel.DANGEROUS,
                message=f"DNS poisoning suspected: local resolver maps '{domain}' "
                        f"to {sorted(rogue)}, not matching trusted DNS "
                        f"{sorted(trusted)} — possible MITM",
                data={"domain": domain,
                      "local": sorted(local),
                      "trusted": sorted(trusted),
                      "rogue": sorted(rogue)},
            ))
            return False
        return True

    async def _local_resolve(self, domain: str) -> set[str]:
        """Resolve A records via the system resolver (/etc/resolv.conf path)."""
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo, domain, None, socket.AF_INET
            )
            return {info[4][0] for info in infos}
        except Exception:
            return set()

    async def _doh_resolve(self, url: str, domain: str) -> set[str]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            data = resp.json()
            return {r["data"] for r in data.get("Answer", []) if r["type"] == 1}
