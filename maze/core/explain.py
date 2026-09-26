"""
What an event means, and what to do about it.

A detection that only a person who already understands the attack can act on
has done half a job. Every event type here gets two sentences: what the
observation actually implies, and the next thing worth doing — phrased for
someone who is looking at their own network at eleven at night, not for a
security team.

The text lives in the translation table (keys `why_<type>` / `do_<type>`); this
module only decides which keys an event maps to, so the two languages stay in
step and the GUI stays free of prose.
"""
from maze.core.events import EventType

# Event types with an explanation. Anything absent falls back to a generic
# line rather than showing a raw key — a missing explanation should look like
# a gap, not like a bug.
EXPLAINED = {
    EventType.ARP_SPOOF, EventType.ARP_SCAN, EventType.ROGUE_AP,
    EventType.ROGUE_DHCP, EventType.ROGUE_RA, EventType.DNS_SPOOF,
    EventType.TLS_CHANGE, EventType.SSL_STRIP, EventType.PORT_SCAN,
    EventType.STEALTH_SCAN, EventType.HOST_SWEEP, EventType.ANOMALY,
    EventType.ATTACK_CHAIN, EventType.UNKNOWN_PROCESS, EventType.DNS_LEAK,
    EventType.DEVICE_NEW, EventType.IP_BLOCKED, EventType.RECON_RESULT,
    EventType.IP_MOVED,
}


def keys_for(event_type) -> tuple[str, str]:
    """(meaning key, next-step key) for an event type."""
    if event_type in EXPLAINED:
        return f"why_{event_type.value}", f"do_{event_type.value}"
    return "why_generic", "do_generic"


def explain(event, translate) -> str:
    """A short block: what happened, what it means, what to do next."""
    why_key, do_key = keys_for(event.type)
    return "\n".join([
        f"{translate('explain_what')}: {event.message}",
        "",
        f"{translate('explain_why')}: {translate(why_key)}",
        f"{translate('explain_do')}: {translate(do_key)}",
    ])
