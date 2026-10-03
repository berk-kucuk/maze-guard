import asyncio
import time
from datetime import datetime

from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.incident import IncidentStore
from maze.core.inventory import DeviceInventory
from maze.network.identity import NetworkIdentity
from maze.core.profile import Profile, ProfileManager, PROFILES
from maze.core.verify import FAIL, INFO, NA, PASS, Verdict, WARN
from maze.utils.ipaddr import AddressSet
from maze.utils.logger import log

# Event types that mean "this source is actively attacking us right now", as
# opposed to "something about this source is odd". Only these trigger active
# recon and, where the profile allows it, an automatic block.
_ACTIVE_ATTACK = {
    EventType.PORT_SCAN, EventType.STEALTH_SCAN, EventType.ATTACK_CHAIN,
}
# Re-run recon against a known source only after this long, so a sustained
# attack does not queue one scan per alert.
_RECON_TTL = 900.0

# How often the kernel log is read back for drop-rule hits, and how far the
# first read reaches back to pick up blocks installed before this session.
_BLOCK_EVIDENCE_INTERVAL = 60.0
_BLOCK_EVIDENCE_BACKFILL = "6h"


class MazeEngine:
    def __init__(self, cfg, helper=None):
        self.bus = EventBus()
        self.profiles = ProfileManager()
        self.cfg = cfg
        self.helper = helper  # HelperClient | None
        self.incidents = IncidentStore()
        # One poller answers "which network is this" for everyone who scopes
        # anything to it: the inventory, the recon cache, the profile watcher.
        self.identity = NetworkIdentity(getattr(cfg, "interface", "") or "")
        self.inventory = DeviceInventory()
        self._modules: dict[str, object] = {}
        self._active: set[str] = set()
        # Why a module refused to start, keyed by module name. A protection
        # that cannot work here used to fail into a log line nobody reads,
        # leaving the interface showing a toggle that flicks back to off with
        # no explanation — the single most common "it doesn't work" report.
        self._errors: dict[str, str] = {}
        self._running = False
        self._recon_at: dict[str, float] = {}
        self._block_log_at: datetime | None = None
        self._fw_state_at = 0.0
        # One whitelist, shared by reference with every detector, so an entry
        # added in Settings applies at once instead of after a restart.
        self.whitelist = AddressSet(getattr(cfg, "whitelist_ips", []))
        # Profile applications stop every module and start a new set, awaiting
        # in between. Two of them in flight at once (a quick double switch, or
        # the startup profile racing a network-triggered one) interleaved and
        # left a mix of both profiles' modules running. They run one at a time.
        self._plan_lock = asyncio.Lock()
        self._last_plan: tuple | None = None
        self._init_modules()
        self.profiles.on_change(self._on_profile_change)
        self.identity.on_change(self._on_network_change)

    def _on_network_change(self, new_id: str, old_id: str) -> None:
        """Tell per-network detectors they are somewhere new.

        Only the ones whose baseline is safe to drop on an identity change.
        The ARP and anomaly detectors track the link themselves (see
        network_info.link_epoch): on a wired link the identity *is* the
        gateway's MAC, so resetting them here would let a spoofed gateway
        erase the very baseline that exposes it.
        """
        if not old_id:
            return
        dns = self._modules.get("dns_validate")
        if dns is not None and hasattr(dns, "network_changed"):
            try:
                dns.network_changed()
            except Exception as exc:
                log.debug(f"dns validator reset failed: {exc}")

    # ------------------------------------------------------------------
    # Module definitions
    # ------------------------------------------------------------------

    def _init_modules(self) -> None:
        from maze.detection.anomaly import AnomalyDetector
        from maze.detection.arp_watch import ARPWatcher
        from maze.detection.rogue_ap import RogueAPDetector
        from maze.detection.dns_validator import DNSValidator
        from maze.detection.tls_monitor import TLSMonitor
        from maze.detection.ssl_strip import SSLStripDetector
        from maze.stealth.hostname_hide import HostnameHider
        from maze.stealth.service_blocker import ServiceBlocker
        from maze.stealth.fingerprint import FingerprintProtector
        from maze.protection.firewall import FirewallManager
        from maze.protection.port_scanner import PortScanDetector
        from maze.protection.process_map import ProcessNetworkMonitor
        from maze.protection.dns_leak import DNSLeakPreventer

        wl = self.whitelist
        self._modules = {
            "arp_watch":       ARPWatcher(self.cfg.interface, whitelist=wl),
            "anomaly":         AnomalyDetector(self.cfg.interface, whitelist=wl),
            "rogue_ap":        RogueAPDetector(self.cfg.interface),
            "dns_validate":    DNSValidator(),
            "tls":             TLSMonitor(),
            "ssl_strip":       SSLStripDetector(),
            "hostname":        HostnameHider(),
            "service_blocker": ServiceBlocker(),
            "fingerprint":     FingerprintProtector(),
            "firewall":        FirewallManager(),
            "port_scan":       PortScanDetector(
                                   self.cfg.interface,
                                   self.cfg.port_scan_threshold,
                                   whitelist=wl,
                               ),
            "process":         ProcessNetworkMonitor(
                                   set(self.cfg.known_processes),
                                   whitelist=wl,
                               ),
            "dns_leak":        DNSLeakPreventer(),
        }

    def set_whitelist(self, entries) -> None:
        """Replace the whitelist every detector consults, in place."""
        self.whitelist.replace(entries)

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def arp_watcher(self):
        return self._modules.get("arp_watch")

    @property
    def process_monitor(self):
        return self._modules.get("process")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self.bus.subscribe_all(self._on_event_for_recon)
        self.bus.subscribe(EventType.DEVICE_FOUND, self._on_device_found)
        self.identity.start()
        await self.identity.refresh()
        if self.helper is not None:
            if self.helper.is_connected():
                await self._check_helper_version()
            asyncio.create_task(self._helper_loop())
        asyncio.create_task(self._ssl_monitor_loop())
        asyncio.create_task(self._sync_firewall_state())
        asyncio.create_task(self._block_evidence_loop())
        await self.bus.emit(Event(
            type=EventType.ENGINE_READY,
            level=ThreatLevel.SAFE,
            message="Maze Guard engine started",
        ))

    async def _helper_loop(self) -> None:
        """Keep the helper connected, and move the modules onto it when it
        (re)appears.

        Capture-based detectors pick helper or direct capture once, at start.
        Started while the daemon was down, they stayed on the direct path —
        which needs root and so saw nothing — after the helper came up, so the
        running profile is re-applied on every reconnect.
        """
        was_connected = self.helper.is_connected()
        while self._running:
            await asyncio.sleep(10)
            if not self.helper.is_connected():
                await self.helper.connect()
            connected = self.helper.is_connected()
            if connected and not was_connected:
                await self._check_helper_version()
            if connected and not was_connected and self._last_plan:
                log.info("privileged helper connected — re-applying the profile")
                try:
                    await self._apply_plan(*self._last_plan)
                except Exception as exc:
                    log.warning(f"re-applying the profile failed: {exc}")
            was_connected = connected

    async def _check_helper_version(self) -> None:
        try:
            await self.helper.version()
        except Exception as exc:
            log.debug(f"helper version check failed: {exc}")
            return
        if getattr(self.helper, "outdated", False):
            log.warning("the privileged helper is older than this interface — "
                        "restart it: sudo systemctl restart maze-guard.service")

    async def _sync_firewall_state(self) -> None:
        """Best-effort: make the incoming-block button reflect the firewall's
        actual (persisted) zone target after a restart."""
        fw = self._fw()
        if fw:
            try:
                await fw.sync_state()
            except Exception as exc:
                log.warning(f"firewall state sync failed: {exc}")

    async def stop(self) -> None:
        self._running = False
        self.identity.stop()
        self.inventory.save()
        await asyncio.gather(
            *[self._stop_module(k) for k in list(self._active)],
            return_exceptions=True,
        )

    # ------------------------------------------------------------------
    # Evidence: what the blocks actually caught
    # ------------------------------------------------------------------

    async def _block_evidence_loop(self) -> None:
        """Fold drop-rule hits from the kernel log back into the dossiers.

        Every rule we install logs what it swallows, so the record of an
        attacker need not stop at the moment we blocked them — whether they
        gave up or kept working at it for an hour is the part that says what
        they were.
        """
        from maze.protection.block_log import available

        if not await asyncio.to_thread(available):
            log.info("kernel journal is not readable — post-block evidence "
                     "will not be collected (add this user to a group that "
                     "can read it, e.g. wheel/adm/systemd-journal)")
            return
        while self._running:
            await asyncio.sleep(_BLOCK_EVIDENCE_INTERVAL)
            try:
                await self.collect_block_evidence()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(f"post-block evidence collection failed: {exc}")

    async def collect_block_evidence(self) -> int:
        """Read one window of drop-rule hits. Returns the number of sources
        the evidence was attached to."""
        from maze.protection.block_log import read

        watermark = self._block_log_at
        since = (watermark.strftime("%Y-%m-%d %H:%M:%S") if watermark
                 else f"-{_BLOCK_EVIDENCE_BACKFILL}")
        records = await read(since=since, after=watermark)
        attached = 0
        newest = watermark
        for src, rec in records.items():
            if rec.last and (newest is None or rec.last > newest):
                newest = rec.last
            if self.incidents.get(src) is None:
                continue          # evidence about a host we never filed
            self.incidents.record_blocked_traffic(src, rec.to_dict())
            attached += 1
        self._block_log_at = newest or datetime.now()
        return attached

    # ------------------------------------------------------------------
    # Device inventory
    # ------------------------------------------------------------------

    async def _on_device_found(self, event: Event) -> None:
        """Fold an ARP sighting into the per-network baseline.

        The watcher's DEVICE_FOUND means "new since this process started",
        which is true of everything after a restart. The inventory answers the
        question people actually have — has this device ever been on *this*
        network — and only that answer is worth an alert.
        """
        mac = (event.data or {}).get("mac", "")
        ip = (event.data or {}).get("ip", "")
        network_id = self.identity.network_id
        if not mac or not network_id:
            return
        try:
            record, is_new = await asyncio.to_thread(
                self.inventory.observe, mac, ip, network_id)
        except Exception as exc:
            log.warning(f"device inventory update failed: {exc}")
            return
        if not is_new or record is None:
            return

        label = record.display_name
        await self.bus.emit(Event(
            type=EventType.DEVICE_NEW,
            level=ThreatLevel.SUSPICIOUS,
            message=f"Unrecognised device joined this network: {ip} "
                    f"({mac})" + (f" — {label}" if label != mac else "")
                    + ("  [randomised MAC]" if record.randomized_mac else ""),
            data={"ip": ip, "mac": mac, "network_id": network_id,
                  "randomized_mac": record.randomized_mac,
                  "vendor": record.vendor, "label": record.label},
        ))

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    @staticmethod
    def _plan_from_config(pcfg) -> tuple[list[str], bool]:
        """Translate a profile/custom-profile config into a module start-list
        plus whether the incoming-block shield should be enabled.

        Uses getattr so it works for both ProfileConfig and CustomProfileConfig.
        Passive detection (ARP/rogue-AP/TLS/SSL-strip/DNS-leak) is always on;
        the rest is gated on the profile's flags.
        """
        to_start = ["firewall", "arp_watch", "anomaly", "rogue_ap", "tls",
                    "ssl_strip", "dns_leak"]
        if getattr(pcfg, "doh_enabled", True):
            to_start.append("dns_validate")
        if getattr(pcfg, "port_scan_detect", True):
            to_start.append("port_scan")
        if getattr(pcfg, "process_monitor", True):
            to_start.append("process")
        if getattr(pcfg, "hide_hostname", False):
            to_start.append("hostname")
        if getattr(pcfg, "fingerprint_protect", False):
            to_start.append("fingerprint")
        if getattr(pcfg, "block_services", False):
            to_start.append("service_blocker")
        return to_start, bool(getattr(pcfg, "block_incoming", False))

    async def _set_incoming_block(self, enabled: bool) -> None:
        """Raise the inbound shield for profiles that want it.

        Deliberately one-way: applying a profile never *lowers* the shield.
        Switching to a profile that does not ask for it means "this profile
        does not manage the shield", not "tear down the protection the user
        currently has" — and a security tool that quietly reduces protection
        as a side effect of an unrelated action is worse than one that leaves
        the decision alone. Lowering it is an explicit toggle, and needs
        authorisation.
        """
        if not enabled:
            return
        fw = self._fw()
        if not fw:
            return
        try:
            await fw.enable_incoming_block()
        except Exception as exc:
            log.warning(f"incoming-block toggle failed: {exc}")

    async def _apply_plan(self, to_start: list[str], block_incoming: bool,
                          label: str, profile_value: str) -> None:
        self._last_plan = (to_start, block_incoming, label, profile_value)
        async with self._plan_lock:
            # Stop everything currently active, then start the profile's set.
            # Stopping stealth modules restores their side effects (avahi
            # restarts, sysctl restored, blocked ports removed), giving clean
            # transitions.
            await asyncio.gather(
                *[self._stop_module(k) for k in list(self._active)],
                return_exceptions=True,
            )
            for key in to_start:
                await self._start_module(key)
            await self._set_incoming_block(block_incoming)
            started = sorted(self._active)

        await self.bus.emit(Event(
            type=EventType.PROFILE_CHANGED,
            level=ThreatLevel.SAFE,
            message=f"{label}: {profile_value}",
            data={"profile": profile_value, "modules": started,
                  "block_incoming": block_incoming},
        ))

    async def apply_profile(self, profile: Profile) -> None:
        to_start, block_incoming = self._plan_from_config(PROFILES[profile])
        await self._apply_plan(to_start, block_incoming,
                               "Profile activated", profile.value)

    def _on_profile_change(self, profile: Profile) -> None:
        asyncio.create_task(self.apply_profile(profile))

    # ------------------------------------------------------------------
    # Individual module control
    # ------------------------------------------------------------------

    async def toggle_module(self, key: str) -> None:
        # Under the plan lock: a toggle landing mid-profile-switch was undone
        # (or duplicated) by the switch's own stop-all/start-set pass.
        async with self._plan_lock:
            if key in self._active:
                await self._stop_module(key)
            else:
                await self._start_module(key)
        await self.bus.emit(Event(
            type=EventType.MODULE_TOGGLED,
            level=ThreatLevel.SAFE,
            message=f"Module {'started' if key in self._active else 'stopped'}: {key}",
            data={"key": key, "active": key in self._active},
        ))

    async def _start_module(self, key: str) -> None:
        if key in self._active:
            return
        mod = self._modules.get(key)
        if mod is None:
            self._errors[key] = f"no such module: {key}"
            return
        try:
            import inspect
            sig = inspect.signature(mod.start)
            if "helper" in sig.parameters:
                await mod.start(self.bus, helper=self.helper)
            else:
                await mod.start(self.bus)
            self._active.add(key)
            self._errors.pop(key, None)
        except Exception as exc:
            self._errors[key] = str(exc) or exc.__class__.__name__
            log.warning(f"Module '{key}' failed to start: {exc}")

    async def _stop_module(self, key: str) -> None:
        mod = self._modules.get(key)
        if mod is None:
            return
        try:
            await mod.stop()
        except Exception as exc:
            log.warning(f"Module '{key}' failed to stop: {exc}")
        self._active.discard(key)

    def module_states(self) -> dict[str, bool]:
        return {k: k in self._active for k in self._modules}

    def module_error(self, key: str) -> str:
        """Why ``key`` is not running, or "" if it started fine."""
        return self._errors.get(key, "")

    def module_detail(self, key: str) -> str:
        """One line about what a running module is actually doing.

        Modules that can be *active yet blind* — a rogue-AP watcher on a wired
        link, a service blocker whose rules never made it into the firewall —
        say so through ``status_detail()``. "Active" on its own is exactly the
        reassurance this application must never give falsely.
        """
        mod = self._modules.get(key)
        detail = getattr(mod, "status_detail", None)
        if detail is None:
            return ""
        try:
            return detail() or ""
        except Exception:
            return ""

    # ── self-tests ────────────────────────────────────────────────────────

    async def verify_module(self, key: str) -> Verdict:
        """Establish, from the system itself, whether ``key`` is in effect.

        Deliberately answerable whether the module is running or not: the point
        of running it in both states is that the two answers differ, and the
        difference *is* the protection. Nothing here changes anything — every
        verifier reads state or feeds synthetic input through the analysis path.
        """
        if key in ("fw_backend", "firewall"):
            return await self._verify_firewall(key)
        mod = self._modules.get(key)
        if mod is None:
            return Verdict(NA, f"no such module: {key}")
        check = getattr(mod, "verify", None)
        if check is None:
            return Verdict(NA, "this module has no self-test yet")
        # A module that was never started has no helper reference, and its
        # self-test then claimed "the privileged helper is not connected"
        # although it was. The test reads system state either way; lend it
        # the helper so the answer is about the system, not about the toggle.
        if getattr(mod, "_helper", False) is None and self.helper is not None:
            mod._helper = self.helper
        try:
            verdict = await check()
        except Exception as exc:
            # A verifier that crashes has told us something real about the
            # module — report that rather than swallowing it.
            return Verdict(FAIL, f"the self-test itself failed: {exc}")
        if key not in self._active and verdict.status == PASS:
            # The system is in the desired state but this module is not the one
            # holding it there, and saying "PASS" would imply otherwise.
            return Verdict(INFO, verdict.summary,
                           verdict.evidence
                           + ["this module is switched off — what the test "
                              "found is the machine's own state, not something "
                              "Maze Guard is maintaining"])
        return verdict

    async def _verify_firewall(self, key: str) -> Verdict:
        state = await self.firewall_state(max_age=0)
        if not state.installed:
            return Verdict(FAIL, "firewalld is not installed, or the "
                                 "privileged helper cannot reach it")
        rules = state.rules or {}
        counted = (f"{len(rules.get('ips', []))} blocked addresses, "
                   f"{len(rules.get('macs', []))} blocked devices, "
                   f"{len(rules.get('ports_tcp', []))} TCP and "
                   f"{len(rules.get('ports_udp', []))} UDP ports")
        if key == "fw_backend":
            if not state.running:
                return Verdict(FAIL,
                               "firewalld is not running: nothing on this host "
                               "is filtered, and no block can be applied",
                               [f"starts at boot: "
                                f"{'yes' if state.enabled else 'no'}"])
            evidence = [f"zone: {state.zone}", f"zone target: {state.target}",
                        counted,
                        f"starts at boot: {'yes' if state.enabled else 'no'}"]
            if state.panic:
                return Verdict(WARN,
                               "firewalld is running in PANIC mode — all "
                               "traffic is dropped, including yours", evidence)
            return Verdict(PASS,
                           f"firewalld is running on zone '{state.zone}' and "
                           f"holding {counted}", evidence)

        # The inbound shield.
        if not state.running:
            return Verdict(FAIL,
                           "the firewall is stopped, so the inbound shield "
                           "cannot be in effect")
        if state.incoming_blocked:
            return Verdict(PASS,
                           f"zone '{state.zone}' has target DROP: unsolicited "
                           f"inbound traffic is discarded, while services you "
                           f"allowed still work",
                           [f"zone target: {state.target}", counted])
        return Verdict(FAIL,
                       f"zone '{state.zone}' has target '{state.target or '?'}': "
                       f"unsolicited inbound traffic is NOT being dropped",
                       [counted])

    async def verify_all(self) -> dict[str, Verdict]:
        """Every self-test, run one after another.

        Sequential on purpose: several of these open sockets or ask the helper,
        and firing thirteen at once turns a diagnostic into a burst of traffic
        that could itself look like the thing being detected.
        """
        results: dict[str, Verdict] = {}
        for key in ["fw_backend", "firewall"] + sorted(self._modules):
            if key == "firewall" and key in results:
                continue
            results[key] = await self.verify_module(key)
        return results

    # ── HTTPS downgrade monitor ───────────────────────────────────────────────

    async def _ssl_monitor_loop(self) -> None:
        """Feed the downgrade detector from the live connection table.

        The previous version asked for the reverse DNS of every port-80 peer and
        compared it against the TLS canary *hostnames*, a match that never
        happens in practice — so the detector was wired to a source that could
        not fire. Addresses are what both sides of this comparison actually
        have: an address we watched serve TLS, and an address we are now
        talking to in the clear.
        """
        await asyncio.sleep(45)
        while self._running:
            await asyncio.sleep(30)
            process_mon = self._modules.get("process")
            ssl_strip = self._modules.get("ssl_strip")
            if not process_mon or not ssl_strip or "ssl_strip" not in self._active:
                continue
            try:
                conns = await process_mon.snapshot()
            except Exception as exc:
                log.debug(f"downgrade monitor: connection snapshot failed: {exc}")
                continue
            # Learn first, then judge — a host seen on both ports in the same
            # snapshot must be recorded as TLS-capable before its plaintext
            # socket is examined.
            for conn in conns:
                if conn.remote_port == 443:
                    ssl_strip.note_tls_endpoint(conn.remote_ip)
            for conn in conns:
                if conn.remote_port == 80 and ssl_strip.knows_tls(conn.remote_ip):
                    asyncio.create_task(
                        ssl_strip.check_downgrade(conn.remote_ip))

    # ── Recon ──────────────────────────────────────────────────────────────

    def _infra_ips(self) -> set[str]:
        """IPs that must never be actively scanned or auto-blocked.

        A port-scan source is taken from a SYN packet's source address, which
        is trivially spoofable. Without this guard an attacker could forge the
        gateway / DNS / an update server as the source and trick us into
        firewalling it — a self-inflicted DoS. Blocks (subprocess) — call off
        the event loop.
        """
        ips: set[str] = set()
        try:
            from maze.utils.network_info import get_interface_info
            info = get_interface_info(self.cfg.interface)
            for v in (info.gateway, info.ip):
                if v and v != "—":
                    ips.add(v)
        except Exception:
            pass
        try:
            from maze.protection.dns_leak import (
                _get_configured_dns_servers, _get_resolved_upstreams,
            )
            ips |= _get_configured_dns_servers()
            ips |= _get_resolved_upstreams()
        except Exception:
            pass
        return ips

    async def _on_event_for_recon(self, event) -> None:
        """Single subscriber that files every event and decides on a response."""
        # File first: the dossier must record what happened even if we choose
        # to take no action, and even for events we never scan on.
        try:
            self.incidents.record(event)
        except Exception as exc:
            log.warning(f"incident recording failed: {exc}")

        if event.level != ThreatLevel.DANGEROUS:
            return
        # Active recon — a port sweep, ping, NetBIOS/mDNS/UPnP probes — is only
        # ever launched at a host that has just actively attacked THIS machine
        # (a port scan, a stealth scan, a correlated attack chain). Those
        # events name the sender, and answering a scan with a scan is
        # proportionate. Everything else DANGEROUS is left passive: an ARP
        # spoof event's "ip" is the VICTIM address (often the gateway), a rogue
        # DHCP/RA source may be the café's own second router, a DNS mismatch
        # names a resolver — sweeping any of those from a laptop on public
        # Wi-Fi is exactly the kind of traffic that gets the tool noticed, and
        # it never changed the response anyway. The dossier still gets filed
        # above; the user can scan by hand from the Threats tab if they want.
        if event.type not in _ACTIVE_ATTACK:
            return
        ip = event.data.get("src") or event.data.get("ip")
        if not ip:
            return
        now = time.monotonic()
        if now - self._recon_at.get(ip, -_RECON_TTL) < _RECON_TTL:
            return
        self._recon_at[ip] = now
        auto_block = bool(getattr(self.cfg, "auto_block", True))
        asyncio.create_task(self._do_recon(ip, auto_block=auto_block,
                                           trigger=event.type.value))

    async def rescan(self, ip: str) -> None:
        """Re-run recon on demand (Threats tab), bypassing the cooldown."""
        self._recon_at[ip] = time.monotonic()
        await self._do_recon(ip, auto_block=False)

    async def _do_recon(self, ip: str, auto_block: bool = False,
                        trigger: str = "") -> None:
        from maze.utils.recon import recon_ip, format_recon
        from maze.protection.dns_leak import _is_private_ip

        # Never touch critical infrastructure — the source may be spoofed.
        infra = await asyncio.to_thread(self._infra_ips)
        if ip in infra or ip in self.whitelist:
            log.info(f"recon/auto-block skipped for infrastructure IP {ip}")
            return
        # Only actively probe on-link (private) hosts. A real attacker on public
        # WiFi shares your L2 and shows a private source; a spoofed *public*
        # source would otherwise make us port-scan an unrelated third party
        # (reflection) and possibly black-hole a legitimate internet host.
        if not _is_private_ip(ip):
            log.info(f"active recon/auto-block skipped for public IP {ip} "
                     f"(spoof/reflection guard)")
            return
        # Block first, ask questions second. Recon is time-boxed but that box
        # is tens of seconds wide, and the decision to block never depended on
        # what it finds — the triggering event already established that. Doing
        # it the other way round meant a confirmed attacker kept scanning for
        # the whole duration of our sweep of them.
        if auto_block:
            await self._block_attacker(ip, trigger)

        try:
            result = await recon_ip(ip)
        except Exception as exc:
            log.warning(f"recon against {ip} failed: {exc}")
            return

        try:
            self.incidents.attach_recon(ip, result.to_dict())
        except Exception as exc:
            log.warning(f"could not attach recon to incident {ip}: {exc}")

        # The dossier is about an address; the inventory is about a device.
        # Both want what the scan learned, and only one of them survives DHCP.
        try:
            if result.mac:
                self.inventory.enrich(result.mac, self.identity.network_id,
                                      vendor=result.vendor,
                                      kind=result.device_kind,
                                      name=result.name)
        except Exception as exc:
            log.debug(f"could not enrich inventory for {ip}: {exc}")

        await self.bus.emit(Event(
            type=EventType.RECON_RESULT,
            level=ThreatLevel.SUSPICIOUS,
            message=format_recon(result),
            data={
                "ip": ip,
                "hostname": result.name,
                "mac": result.mac,
                "vendor": result.vendor,
                "open_ports": result.open_ports,
                "banners": result.banners,
                "os_hint": result.os_hint,
                "netbios_name": result.netbios_name,
                "mdns_name": result.mdns_name,
                "risk_score": result.risk_score,
                "findings": result.findings,
                "latency_ms": result.latency_ms,
            },
        ))

    async def _block_attacker(self, ip: str, trigger: str) -> None:
        """Drop a confirmed attacker immediately, and say why.

        Identity here is only what the dossier already knows (ARP, earlier
        events); the recon that follows enriches it through RECON_RESULT.
        """
        if not await self.block_ip(ip):
            log.warning(f"auto-block of {ip} failed: {self.firewall_error()}")
            return
        att = self.incidents.get(ip)
        known = ""
        if att:
            if att.mac:
                known += f" | mac={att.mac}"
            if att.vendor:
                known += f" ({att.vendor})"
        await self.bus.emit(Event(
            type=EventType.IP_BLOCKED,
            level=ThreatLevel.DANGEROUS,
            message=f"Auto-blocked {ip} — "
                    f"{(trigger or 'confirmed attack').replace('_', ' ')}"
                    + known,
            data={"ip": ip, "trigger": trigger,
                  "mac": att.mac if att else "",
                  "vendor": att.vendor if att else ""},
        ))

    # ── Firewall convenience API ───────────────────────────────────────────

    @property
    def firewall(self):
        return self._modules.get("firewall")

    def _fw(self):
        fw = self.firewall
        if fw:
            fw._helper = self.helper
        return fw

    async def block_ip(self, ip: str) -> bool:
        """Drop a source address, and its hardware address where we know it.

        An address block alone is porous by design: the host renews its DHCP
        lease, or simply sets a static address, and the rule now guards an
        address nobody uses. The MAC is the device — only meaningful on the
        local segment, which is precisely the threat this tool exists for.
        """
        fw = self._fw()
        ok = await fw.block_ip(ip) if fw else False
        if ok:
            # Reflect the block in the port-scan detector so the dashboard
            # scan table can show it as BLOCKED (covers both auto and manual).
            pm = self._modules.get("port_scan")
            if pm is not None and hasattr(pm, "mark_blocked"):
                pm.mark_blocked(ip)
            self.incidents.mark_blocked(ip, True)
            if getattr(self.cfg, "block_by_mac", True):
                await self._block_mac_for(ip)
        return ok

    async def unblock_ip(self, ip: str) -> bool:
        fw = self._fw()
        ok = await fw.unblock_ip(ip) if fw else False
        if ok:
            pm = self._modules.get("port_scan")
            if pm is not None:
                pm.blocked_ips.discard(ip)
            self.incidents.mark_blocked(ip, False)
            # Whatever the block installed, the unblock removes. Leaving a MAC
            # rule behind after the user unblocked an address would be a silent
            # block with nothing in the interface admitting to it.
            mac = self.mac_for(ip)
            if mac and fw:
                await fw.unblock_mac(mac)
        return ok

    def mac_for(self, ip: str) -> str:
        """The hardware address behind an IP, from whichever layer knows it:
        the dossier, the live ARP table, or the inventory."""
        att = self.incidents.get(ip)
        if att and att.mac:
            return att.mac
        watcher = self.arp_watcher
        if watcher:
            mac = (watcher.devices.get(ip) or {}).get("mac", "")
            if mac:
                return mac
        record = self.inventory.by_ip(ip, self.identity.network_id)
        return record.mac if record else ""

    async def unblock_mac(self, mac: str) -> bool:
        fw = self._fw()
        return await fw.unblock_mac(mac) if fw else False

    async def _block_mac_for(self, ip: str) -> bool:
        fw = self._fw()
        mac = self.mac_for(ip)
        if not (fw and mac):
            return False
        if not await fw.block_mac(mac):
            log.debug(f"MAC block for {ip} ({mac}) not applied: "
                      f"{fw.last_error}")
            return False
        self.incidents.add_action(ip, f"hardware address {mac} blocked")
        return True

    async def block_port(self, port: int, proto: str = "tcp") -> bool:
        fw = self._fw()
        return await fw.block_port(port, proto) if fw else False

    async def unblock_port(self, port: int, proto: str = "tcp") -> bool:
        fw = self._fw()
        return await fw.unblock_port(port, proto) if fw else False

    async def list_fw_rules(self) -> dict:
        fw = self._fw()
        return await fw.list_rules() if fw else {"ips": [], "ports_tcp": [],
                                                 "ports_udp": [], "macs": []}

    async def toggle_incoming_block(self) -> bool:
        fw = self._fw()
        if not fw:
            return False
        # Decide from live state, not a cached flag: the target is written
        # with --permanent and can be changed by anything on the system.
        state = await fw.sync_state()
        ok = (await fw.disable_incoming_block() if state.incoming_blocked
              else await fw.enable_incoming_block())
        if ok:
            await self._announce_firewall(
                "Inbound traffic shield disabled" if state.incoming_blocked
                else "Inbound traffic shield enabled",
                ThreatLevel.SUSPICIOUS if state.incoming_blocked
                else ThreatLevel.SAFE)
        return ok

    async def is_incoming_blocked(self) -> bool:
        fw = self._fw()
        return fw.is_incoming_blocked() if fw else False

    async def firewall_state(self, max_age: float = 8.0):
        """Live firewall state for the UI. Never raises.

        Three widgets poll this on their own timers; each read is several
        round-trips to the helper and two firewall-cmd invocations, so answers
        younger than ``max_age`` are shared instead of re-fetched. Actions that
        change the firewall pass max_age=0 to force a fresh read.
        """
        from maze.protection.firewall import FirewallState
        fw = self._fw()
        if not fw:
            return FirewallState()
        now = time.monotonic()
        # A reading taken before the last change is not reused: the UI used
        # to show the pre-block rules for up to max_age after a block.
        fresh = self._fw_state_at > getattr(fw, "changed_at", 0.0)
        if max_age > 0 and fresh and now - self._fw_state_at < max_age:
            return fw.state
        try:
            state = await fw.sync_state()
            self._fw_state_at = now
            return state
        except Exception as exc:
            log.warning(f"firewall state read failed: {exc}")
            return FirewallState()

    async def set_firewall_enabled(self, enabled: bool) -> bool:
        """Start or stop the firewall backend itself."""
        fw = self._fw()
        if not fw:
            return False
        ok = (await fw.enable_firewall() if enabled
              else await fw.disable_firewall())
        if ok:
            # SUSPICIOUS, not DANGEROUS, when switched off: the threat meter
            # reports what was detected on the network, and turning a red
            # "attack" indicator on for the user's own deliberate click would
            # teach them to ignore it. The message says plainly what changed.
            await self._announce_firewall(
                "Firewall started" if enabled
                else "Firewall stopped — this host is no longer filtered",
                ThreatLevel.SAFE if enabled else ThreatLevel.SUSPICIOUS)
        return ok

    def firewall_error(self) -> str:
        fw = self.firewall
        return getattr(fw, "last_error", "") if fw else "firewall module missing"

    async def _announce_firewall(self, message: str, level: ThreatLevel) -> None:
        await self.bus.emit(Event(
            type=EventType.FIREWALL_CHANGED, level=level, message=message,
        ))

    async def flush_fw(self) -> None:
        fw = self._fw()
        if fw:
            await fw.flush()

    async def apply_custom_profile(self, profile_cfg) -> None:
        """Apply a CustomProfileConfig, honouring all of its flags."""
        to_start, block_incoming = self._plan_from_config(profile_cfg)
        await self._apply_plan(to_start, block_incoming,
                               "Custom profile activated",
                               getattr(profile_cfg, "name", "?"))
