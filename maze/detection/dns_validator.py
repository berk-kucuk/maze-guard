import asyncio
import ipaddress
import socket
import time
import httpx
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.verify import FAIL, PASS, Verdict, WARN
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

# The same finding is repeated at most this often on one network.
_REALERT_AFTER = 3600.0

# Addresses a local network hands out: what a captive portal or a DNS-
# intercepting router answers with. Listed explicitly, because Python's
# is_private also covers reserved and documentation ranges.
_LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def _classify(addresses: set[str]) -> str:
    """What kind of wrong answer this is.

    "sinkhole"  0.0.0.0, loopback, ::  — a filter (Pi-hole, AdGuard Home, a
                router's parental control, the distro's own blocklist) refusing
                the name. Blocklists routinely include public DoH hostnames
                like these canaries so devices cannot bypass them. Not an
                attack: nothing is redirected anywhere.
    "private"   RFC 1918 / CGNAT / link-local — a captive portal or a network
                that intercepts DNS. Worth knowing, not proof of an attack.
    "public"    a routable address the trusted resolvers never gave — traffic
                is being sent somewhere else. That is poisoning.
    """
    kinds = set()
    for text in addresses:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            kinds.add("public")
            continue
        if ip.is_unspecified or ip.is_loopback:
            kinds.add("sinkhole")
        elif any(ip.version == net.version and ip in net for net in _LOCAL_NETS):
            kinds.add("private")
        else:
            kinds.add("public")
    for kind in ("public", "private", "sinkhole"):
        if kind in kinds:
            return kind
    return "public"


class DNSValidator:
    def __init__(self):
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._warned: set[str] = set()
        self._alerted: dict[str, float] = {}    # domain → monotonic time

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def network_changed(self) -> None:
        """A new network has a new resolver: judge it afresh."""
        self._warned.clear()
        self._alerted.clear()

    async def verify(self) -> Verdict:
        """Run one real cross-check now, and report both sides of it."""
        domain = _CANARY_DOMAINS[0]
        answers, reachable = [], 0
        trusted: set[str] = set()
        for name, url in DOH_RESOLVERS.items():
            try:
                got = await asyncio.wait_for(
                    self._doh_resolve(url, domain), timeout=8)
            except Exception as exc:
                answers.append(f"{name}: unreachable — {exc}")
                continue
            if got:
                reachable += 1
                trusted |= got
                answers.append(f"{name}: {', '.join(sorted(got))}")
            else:
                answers.append(f"{name}: empty answer")

        local = await self._local_resolve(domain)
        answers.append(f"this machine's resolver: "
                       f"{', '.join(sorted(local)) or 'no answer'}")
        if reachable < 2:
            return Verdict(FAIL,
                           f"only {reachable} of {len(DOH_RESOLVERS)} trusted "
                           f"resolvers answered — with fewer than two there is "
                           f"no baseline, and poisoning cannot be detected",
                           answers)
        rogue = local - trusted
        if rogue and _classify(rogue) == "sinkhole":
            return Verdict(WARN,
                           f"this machine's resolver blocks {domain} "
                           f"({sorted(rogue)}) — a DNS filter such as Pi-hole; "
                           f"the canary cannot be cross-checked through it",
                           answers)
        if rogue:
            return Verdict(FAIL,
                           f"this machine's resolver maps {domain} to "
                           f"{sorted(rogue)}, which none of the trusted "
                           f"resolvers returned — DNS is being tampered with",
                           answers)
        return Verdict(PASS,
                       f"{reachable} independent resolvers agree with this "
                       f"machine's answer for {domain}", answers)

    def status_detail(self) -> str:
        if "__baseline__" in self._warned:
            return ("fewer than two DoH resolvers are reachable — local DNS "
                    "answers cannot be cross-checked")
        return (f"cross-checking {len(_CANARY_DOMAINS)} domains against "
                f"{len(DOH_RESOLVERS)} independent resolvers")

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
                # Not an event: an unreachable DoH service is a limitation of
                # this network (captive portal, DoH blocked by policy), not a
                # threat, and it used to land in the threat list — as a
                # DNS_SPOOF, no less. It shows in the module's status instead.
            return True
        # Recovered — allow the warning again if it breaks a second time.
        self._warned.discard("__baseline__")

        local = await self._local_resolve(domain)
        if not local:
            return True

        rogue = local - trusted
        if not rogue:
            return True
        kind = _classify(rogue)
        if kind == "sinkhole":
            log.info(f"DNSValidator: '{domain}' is blocked by the local "
                     f"resolver ({sorted(rogue)}) — a DNS filter, not poisoning")
            return True
        now = time.monotonic()
        if now - self._alerted.get(domain, -_REALERT_AFTER) < _REALERT_AFTER:
            return False
        self._alerted[domain] = now
        data = {"domain": domain, "local": sorted(local),
                "trusted": sorted(trusted), "rogue": sorted(rogue),
                "kind": kind}
        if kind == "private":
            await self._emit(Event(
                type=EventType.DNS_SPOOF,
                level=ThreatLevel.SUSPICIOUS,
                message=f"This network's DNS redirects '{domain}' to a local "
                        f"address {sorted(rogue)} — usually a captive portal "
                        f"or a network that intercepts DNS",
                data=data,
            ))
        else:
            await self._emit(Event(
                type=EventType.DNS_SPOOF,
                level=ThreatLevel.DANGEROUS,
                message=f"DNS poisoning suspected: local resolver maps '{domain}' "
                        f"to {sorted(rogue)}, not matching trusted DNS "
                        f"{sorted(trusted)} — possible MITM",
                data=data,
            ))
        return False

    async def _emit(self, event: Event) -> None:
        if self._bus:
            await self._bus.emit(event)

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
