"""
One answer to "which network are we on", shared by everything that asks.

Three separate pollers used to ask this question — the auto-profile watcher,
the device-intel cache and (once there was an inventory) the device inventory.
Three shell-outs to `iwgetid`/`ip route` on three different schedules meant
three slightly different ideas of the current network at any given moment, and
a change was noticed at three different times. Anything scoped to "this
network" — a cached dossier, a device baseline, a profile — has to agree on
where that scope starts and ends, so the question is asked in one place.

Identity is the SSID for wireless and the default gateway's MAC for wired (see
network_info.current_network_id): both survive a DHCP lease change, which an
IP or subnet does not.
"""
import asyncio

from maze.utils.logger import log
from maze.utils.network_info import (current_network_id, get_default_gateway,
                                     network_aliases)

_POLL_INTERVAL = 15.0


class NetworkIdentity:
    """Polls the attached network's identity and announces changes."""

    def __init__(self, interface: str = "", poll_interval: float = _POLL_INTERVAL):
        self.interface = interface or ""
        self._poll = poll_interval
        self._network_id = ""
        self._gateway = ""
        self._aliases: set[str] = set()
        self._listeners: list = []
        self._task: asyncio.Task | None = None

    # ── state ────────────────────────────────────────────────────────────

    @property
    def network_id(self) -> str:
        return self._network_id

    @property
    def gateway(self) -> str:
        return self._gateway

    @property
    def aliases(self) -> set[str]:
        """Every id the current network answers to (see network_aliases)."""
        return set(self._aliases) | ({self._network_id} if self._network_id else set())

    def set_interface(self, interface: str) -> None:
        """Point at a different interface. Treated as a network change, because
        it is one — whatever was true of the old link says nothing about this."""
        if not interface or interface == self.interface:
            return
        self.interface = interface
        old, self._network_id = self._network_id, ""
        self._gateway = ""
        self._aliases = set()
        if old:
            self._announce("", old)

    # ── subscriptions ────────────────────────────────────────────────────

    def on_change(self, callback) -> None:
        """Register callback(new_id, old_id). Called for the first identity we
        establish as well, so a listener never has to poll for the initial
        value it was created too early to see."""
        self._listeners.append(callback)

    def _announce(self, new_id: str, old_id: str) -> None:
        for cb in list(self._listeners):
            try:
                cb(new_id, old_id)
            except Exception as exc:      # one bad listener must not stop the rest
                log.warning(f"network identity listener failed: {exc}")

    # ── polling ──────────────────────────────────────────────────────────

    async def refresh(self) -> str:
        """Re-read the identity now. Returns the current value.

        An unreadable identity (link down, tooling missing) leaves the last
        known value in place rather than announcing a change: a transient
        failure must not invalidate everything scoped to a network we are
        probably still on.
        """
        try:
            net_id = await asyncio.to_thread(current_network_id, self.interface)
            gateway = await asyncio.to_thread(get_default_gateway, self.interface)
            aliases = (await asyncio.to_thread(network_aliases, self.interface)
                       if net_id else set())
        except Exception as exc:
            log.debug(f"network identity lookup failed: {exc}")
            return self._network_id

        if gateway:
            self._gateway = gateway
        if net_id:
            self._aliases = aliases
        if not net_id or net_id == self._network_id:
            return self._network_id

        old, self._network_id = self._network_id, net_id
        if old:
            log.info(f"network changed: {old} → {net_id}")
        else:
            log.info(f"network identified: {net_id}")
        self._announce(net_id, old)
        return net_id

    def start(self) -> None:
        """Begin polling. Idempotent, and a no-op without a running loop — the
        GUI builds its widgets before the loop starts, so callers retry."""
        if self._task is not None and not self._task.done():
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self._task = asyncio.ensure_future(self._run())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        while True:
            try:
                await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(f"network identity poll failed: {exc}")
            await asyncio.sleep(self._poll)
