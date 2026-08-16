import asyncio
import time

from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.incident import IncidentStore
from maze.core.profile import Profile, ProfileManager, PROFILES
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


class MazeEngine:
    def __init__(self, cfg, helper=None):
        self.bus = EventBus()
        self.profiles = ProfileManager()
        self.cfg = cfg
        self.helper = helper  # HelperClient | None
        self.incidents = IncidentStore()
        self._modules: dict[str, object] = {}
        self._active: set[str] = set()
        self._running = False
        self._recon_at: dict[str, float] = {}
        self._fw_state_at = 0.0
        self._init_modules()
        self.profiles.on_change(self._on_profile_change)

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

        wl = list(getattr(self.cfg, "whitelist_ips", []))
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
        if self.helper:
            asyncio.create_task(self.helper.maintain_connection())
        asyncio.create_task(self._ssl_monitor_loop())
        asyncio.create_task(self._sync_firewall_state())
        await self.bus.emit(Event(
            type=EventType.ENGINE_READY,
            level=ThreatLevel.SAFE,
            message="Maze Guard engine started",
        ))

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
        await asyncio.gather(
            *[self._stop_module(k) for k in list(self._active)],
            return_exceptions=True,
        )

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
        # Stop everything currently active, then start the profile's set.
        # Stopping stealth modules restores their side effects (avahi restarts,
        # sysctl restored, blocked ports removed), giving clean transitions.
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
            return
        try:
            import inspect
            sig = inspect.signature(mod.start)
            if "helper" in sig.parameters:
                await mod.start(self.bus, helper=self.helper)
            else:
                await mod.start(self.bus)
            self._active.add(key)
        except Exception as exc:
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

    # ── SSL strip monitor ─────────────────────────────────────────────────────

    async def _ssl_monitor_loop(self) -> None:
        """
        Periodically check if hosts we have verified TLS certs for are now
        accepting HTTP connections — strong signal for an SSLStrip MITM.
        """
        import socket as _socket
        await asyncio.sleep(90)
        while self._running:
            await asyncio.sleep(60)
            process_mon = self._modules.get("process")
            ssl_strip   = self._modules.get("ssl_strip")
            tls_mon     = self._modules.get("tls")
            if not process_mon or not ssl_strip or "ssl_strip" not in self._active:
                continue
            known_https = set(getattr(tls_mon, "_spki_store", {}).keys())
            if not known_https:
                continue
            try:
                conns = await process_mon.snapshot()
                for conn in conns:
                    if conn.remote_port != 80:
                        continue
                    try:
                        hostname = await asyncio.wait_for(
                            asyncio.to_thread(
                                lambda ip=conn.remote_ip: _socket.gethostbyaddr(ip)[0]
                            ),
                            timeout=2.0,
                        )
                        if hostname in known_https:
                            asyncio.create_task(
                                ssl_strip.check(f"http://{hostname}")
                            )
                    except Exception:
                        pass
            except Exception:
                pass

    # ── Recon ──────────────────────────────────────────────────────────────

    def _infra_ips(self) -> set[str]:
        """IPs that must never be actively scanned or auto-blocked.

        A port-scan source is taken from a SYN packet's source address, which
        is trivially spoofable. Without this guard an attacker could forge the
        gateway / DNS / an update server as the source and trick us into
        firewalling it — a self-inflicted DoS. Blocks (subprocess) — call off
        the event loop.
        """
        ips: set[str] = set(getattr(self.cfg, "whitelist_ips", []))
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
        ip = event.data.get("src") or event.data.get("ip")
        if not ip:
            return
        now = time.monotonic()
        if now - self._recon_at.get(ip, -_RECON_TTL) < _RECON_TTL:
            return
        self._recon_at[ip] = now
        # Auto-block only for confirmed active attackers. ARP/gateway sources
        # are excluded — blocking the default gateway cuts connectivity, which
        # is exactly what an attacker forging that source would want.
        auto_block = (event.type in _ACTIVE_ATTACK
                      and bool(getattr(self.cfg, "auto_block", True)))
        asyncio.create_task(self._do_recon(ip, auto_block=auto_block))

    async def rescan(self, ip: str) -> None:
        """Re-run recon on demand (Threats tab), bypassing the cooldown."""
        self._recon_at[ip] = time.monotonic()
        await self._do_recon(ip, auto_block=False)

    async def _do_recon(self, ip: str, auto_block: bool = False) -> None:
        from maze.utils.recon import recon_ip, format_recon
        from maze.protection.dns_leak import _is_private_ip

        # Never touch critical infrastructure — the source may be spoofed.
        infra = await asyncio.to_thread(self._infra_ips)
        if ip in infra:
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
        try:
            result = await recon_ip(ip)
        except Exception as exc:
            log.warning(f"recon against {ip} failed: {exc}")
            return

        try:
            self.incidents.attach_recon(ip, result.to_dict())
        except Exception as exc:
            log.warning(f"could not attach recon to incident {ip}: {exc}")

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
        if not auto_block:
            return
        if await self.block_ip(ip):
            await self.bus.emit(Event(
                type=EventType.IP_BLOCKED,
                level=ThreatLevel.DANGEROUS,
                message=f"Auto-blocked {ip} after recon"
                        + (f" | os={result.os_hint}" if result.os_hint else "")
                        + (f" | risk={result.risk_score}/100" if result.risk_score else "")
                        + (f" | open_ports={[p for p, _ in result.open_ports[:4]]}"
                           if result.open_ports else ""),
                data={"ip": ip, "mac": result.mac, "vendor": result.vendor,
                      "open_ports": result.open_ports, "os_hint": result.os_hint,
                      "risk_score": result.risk_score},
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
        fw = self._fw()
        ok = await fw.block_ip(ip) if fw else False
        if ok:
            # Reflect the block in the port-scan detector so the dashboard
            # scan table can show it as BLOCKED (covers both auto and manual).
            pm = self._modules.get("port_scan")
            if pm is not None and hasattr(pm, "mark_blocked"):
                pm.mark_blocked(ip)
            self.incidents.mark_blocked(ip, True)
        return ok

    async def unblock_ip(self, ip: str) -> bool:
        fw = self._fw()
        ok = await fw.unblock_ip(ip) if fw else False
        if ok:
            pm = self._modules.get("port_scan")
            if pm is not None:
                pm.blocked_ips.discard(ip)
            self.incidents.mark_blocked(ip, False)
        return ok

    async def block_port(self, port: int, proto: str = "tcp") -> bool:
        fw = self._fw()
        return await fw.block_port(port, proto) if fw else False

    async def unblock_port(self, port: int, proto: str = "tcp") -> bool:
        fw = self._fw()
        return await fw.unblock_port(port, proto) if fw else False

    async def list_fw_rules(self) -> dict:
        fw = self._fw()
        return await fw.list_rules() if fw else {"ips": [], "ports_tcp": [], "ports_udp": []}

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

    async def firewall_state(self, max_age: float = 2.0):
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
        if max_age > 0 and now - self._fw_state_at < max_age:
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
