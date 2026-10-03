"""
Address classification, for both families.

Several decisions in this application turn on one question: *is this address
on my link, or somewhere out on the internet?* Blocking, active reconnaissance
and DNS-leak analysis all ask it, and getting it wrong in the permissive
direction means scanning or black-holing an uninvolved third party because a
packet header said so.

It used to be answered by string prefixes ("10.", "192.168.") which was correct
as far as it went and completely blind to IPv6 — so an attacker on the same
segment using a link-local address was, to every one of those checks, not on
the link at all. This uses the stdlib parser and answers for both families.
"""
import ipaddress

# Special IPv4 values that are not really addresses. Treated as local so that
# nothing ever tries to probe or block them.
_V4_SPECIAL = {"0.0.0.0", "255.255.255.255"}

# Written out rather than deferred to ipaddress.is_private, which is broader
# than this application means: it also covers the documentation ranges
# (192.0.2/24, 198.51.100/24, 203.0.113/24) and the benchmarking block. Those
# are not routable, but they are not on anyone's link either — and one of them
# is the deliberately-unreachable address the DNS-leak self-test fires through
# the detector, which stops flagging it the moment it counts as local.
_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    # IPv4 — RFC 1918, loopback, link-local
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",
    # IPv6 — unique local, link-local, loopback, deprecated site-local
    "fc00::/7", "fe80::/10", "::1/128", "fec0::/10",
))


def parse(ip: str):
    """An ip_address object, or None if this is not an address at all."""
    if not ip:
        return None
    try:
        # Strip a zone index ("fe80::1%wlan0") — it names an interface, not a
        # different address, and the parser rejects it.
        return ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None


def is_private(ip: str) -> bool:
    """True for anything that can only exist on a local network.

    IPv4: RFC 1918, loopback, link-local (169.254/16), and the two special
    values above. IPv6: unique local (fc00::/7), link-local (fe80::/10) and
    loopback. Deliberately NOT true for global unicast IPv6 — a device with a
    routable v6 address is reachable from the internet, and treating it as
    on-link would hand back the reflection hazard this exists to prevent.
    """
    if ip in _V4_SPECIAL:
        return True
    addr = parse(ip)
    if addr is None:
        return False
    return any(addr in net for net in _LOCAL_NETS
               if net.version == addr.version)


def is_ipv6(ip: str) -> bool:
    addr = parse(ip)
    return addr is not None and addr.version == 6


def is_link_local(ip: str) -> bool:
    addr = parse(ip)
    return addr is not None and addr.is_link_local


def family(ip: str) -> str:
    """"ipv4" / "ipv6" / "" — the word firewalld wants."""
    addr = parse(ip)
    if addr is None:
        return ""
    return "ipv6" if addr.version == 6 else "ipv4"


def same_family(a: str, b: str) -> bool:
    fa, fb = family(a), family(b)
    return bool(fa) and fa == fb


class AddressSet:
    """User-entered addresses and networks, matched the way people mean them.

    The whitelist accepted "10.0.0.0/8" in the interface while every detector
    compared it with ``src in set(...)`` — an exact string match no address
    ever makes, so a whitelisted network was silently not whitelisted. Each
    detector also took its own copy at startup, so an entry added in Settings
    did nothing until a restart. One instance is shared by every detector and
    updated in place.
    """

    def __init__(self, entries=()):
        self._exact: set[str] = set()
        self._nets: list = []
        self.replace(entries)

    @classmethod
    def of(cls, entries) -> "AddressSet":
        """Share an existing set rather than copying it."""
        return entries if isinstance(entries, cls) else cls(entries or ())

    def replace(self, entries) -> None:
        exact, nets = set(), []
        for raw in entries or ():
            text = str(raw).strip()
            if not text:
                continue
            if "/" in text:
                try:
                    nets.append(ipaddress.ip_network(text, strict=False))
                    continue
                except ValueError:
                    pass
            exact.add(text)
        self._exact, self._nets = exact, nets

    def __contains__(self, ip) -> bool:
        if not ip:
            return False
        if ip in self._exact:
            return True
        if not self._nets:
            return False
        addr = parse(ip)
        return addr is not None and any(
            addr in net for net in self._nets if net.version == addr.version)

    def __iter__(self):
        yield from self._exact
        yield from (str(n) for n in self._nets)

    def __len__(self) -> int:
        return len(self._exact) + len(self._nets)

    def __repr__(self) -> str:
        return f"AddressSet({sorted(self)})"
