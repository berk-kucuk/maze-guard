"""
Self-tests: proving a protection is in effect, from outside the module.

Every module already reports whether it started and what it thinks it is doing.
Neither answer is evidence. A module can start cleanly and watch a dead capture;
it can hold a list of firewall rules that firewalld never accepted; it can have
stopped a daemon that systemd started again a second later. The interface said
"Active" through all three, and that is the failure this application exists to
avoid — a security tool that looks healthy while protecting nothing.

A verifier answers a different question: **is the thing true right now?** It
asks the system, not the module — systemd for a unit's state, firewalld for its
rule list, the kernel for a sysctl, a live socket for reachability — or it feeds
synthetic input through the real analysis path and checks that the alarm fires.
It never trusts a flag the module set about itself.

The verdict is deliberately phrased as *what is currently true*, not as
"working / not working". That is what makes running the test with the toggle off
and then on informative: the two answers describe the same system in two
states, and the difference between them is the protection.
"""
from dataclasses import dataclass, field

PASS = "pass"     # the protection is in effect, and that was confirmed
FAIL = "fail"     # it is not in effect, or the check proved it broken
WARN = "warn"     # it works as far as can be told, but something is degraded
INFO = "info"     # nothing is wrong; there is simply nothing to be in effect
NA = "na"         # this module has no self-test


@dataclass
class Verdict:
    """The result of one self-test.

    ``summary`` is one sentence stating what is true, written to be read by
    someone who did not write the module. ``evidence`` holds the raw facts it
    was derived from — the systemctl output, the rule that was or was not
    found, the packet counts — so the answer can be checked rather than
    believed.
    """
    status: str
    summary: str
    evidence: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status in (PASS, INFO)

    def as_text(self) -> str:
        lines = [self.summary]
        lines += [f"  · {e}" for e in self.evidence]
        return "\n".join(lines)


def merge(*verdicts: Verdict) -> Verdict:
    """Combine several checks into the one a user should act on.

    The worst status wins, because a protection with one broken half is broken.
    Every summary is kept, since "which half" is the useful part.
    """
    order = {PASS: 0, INFO: 0, WARN: 1, NA: 1, FAIL: 2}
    live = [v for v in verdicts if v is not None]
    if not live:
        return Verdict(NA, "nothing to check")
    worst = max(live, key=lambda v: order.get(v.status, 1))
    evidence: list[str] = []
    for v in live:
        if v is not worst:
            evidence.append(v.summary)
        evidence += v.evidence
    return Verdict(worst.status, worst.summary, evidence)


async def capture_feed(helper, capture: str, seen: int, what: str) -> Verdict:
    # ``what`` names the packets this detector cares about, as a plural noun
    # phrase — "ARP packets from other hosts" — because every sentence below
    # counts them.
    """Judge a detector's packet feed, distinguishing quiet from dead.

    A detector that has received nothing is the normal state of a healthy
    machine on a calm network — and it is also exactly what a broken capture
    looks like. Reporting both as "degraded" trains people to ignore the
    warning, which costs more than it saves.

    The daemon's own counters settle it: if the capture has processed traffic
    while this detector saw none of it, then nothing has been aimed at this
    machine, and that is the good news it deserves to be reported as.
    """
    if capture == "direct":
        return Verdict(WARN,
                       "capturing without the privileged helper — this needs "
                       "root, and sees nothing without it",
                       [f"{seen} {what} so far"])
    if not capture:
        return Verdict(FAIL, "no capture is attached: nothing is being watched")
    if seen:
        return Verdict(PASS, f"the capture is live: {seen} {what} examined")

    stats = await helper.capture_stats() if helper else {}
    packets = int(stats.get("packets", 0) or 0)
    if not stats:
        return Verdict(WARN,
                       "the capture is attached but nothing has reached this "
                       "detector yet, and the daemon is too old to say whether "
                       "it is seeing traffic at all")
    if packets:
        return Verdict(PASS,
                       f"the capture is live and nothing has been aimed at "
                       f"this machine: the daemon has processed {packets} "
                       f"packets on {stats.get('iface') or 'the link'}, and "
                       f"none of them were {what}",
                       [f"capture running for {stats.get('uptime_s', 0)}s"])
    return Verdict(FAIL,
                   f"the capture has processed no packets at all in "
                   f"{stats.get('uptime_s', 0)}s on "
                   f"{stats.get('iface') or 'the link'} — the feed is dead, "
                   f"not quiet")
