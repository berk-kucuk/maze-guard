import asyncio
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.core.profile import Profile, ProfileManager, PROFILES
from maze.utils.logger import log


class MazeEngine:
    def __init__(self, cfg, helper=None):
        self.bus = EventBus()
        self.profiles = ProfileManager()
        self.cfg = cfg
        self.helper = helper  # HelperClient | None
        self._modules: dict[str, object] = {}
        self._active: set[str] = set()
        self._running = False
        self._recon_done: set[str] = set()
        self._init_modules()
        self.profiles.on_change(self._on_profile_change)

    # ------------------------------------------------------------------
    # Module definitions
    # ------------------------------------------------------------------

    def _init_modules(self) -> None:
        from maze.detection.arp_watch import ARPWatcher
        from maze.detection.rogue_ap import RogueAPDetector
        from maze.detection.dns_validator import DNSValidator
        from maze.detection.tls_monitor import TLSMonitor
        from maze.detection.ssl_strip import SSLStripDetector
        from maze.stealth.mac_changer import MACChanger
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
            "rogue_ap":        RogueAPDetector(self.cfg.interface),
            "dns_validate":    DNSValidator(),
            "tls":             TLSMonitor(),
            "ssl_strip":       SSLStripDetector(),
            "mac":             MACChanger(self.cfg.interface, self.cfg.mac_rotation_minutes),
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
        await self.bus.emit(Event(
            type=EventType.ENGINE_READY,
            level=ThreatLevel.SAFE,
            message="Maze Guard engine started",
        ))

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
        to_start = ["arp_watch", "rogue_ap", "tls", "ssl_strip", "dns_leak"]
        if getattr(pcfg, "doh_enabled", True):
            to_start.append("dns_validate")
        if getattr(pcfg, "port_scan_detect", True):
            to_start.append("port_scan")
        if getattr(pcfg, "process_monitor", True):
            to_start.append("process")
        if getattr(pcfg, "mac_randomize", False):
            to_start.append("mac")
        if getattr(pcfg, "hide_hostname", False):
            to_start.append("hostname")
        if getattr(pcfg, "fingerprint_protect", False):
            to_start.append("fingerprint")
        if getattr(pcfg, "block_services", False):
            to_start.append("service_blocker")
        return to_start, bool(getattr(pcfg, "block_incoming", False))

    async def _set_incoming_block(self, enabled: bool) -> None:
        fw = self._fw()
        if not fw:
            return
        try:
            if enabled:
                await fw.enable_incoming_block()
            else:
                await fw.disable_incoming_block()
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
            known_https = set(getattr(tls_mon, "_cert_store", {}).keys())
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

    async def _on_event_for_recon(self, event) -> None:
        from maze.core.events import ThreatLevel, EventType
        if event.level != ThreatLevel.DANGEROUS:
            return
        ip = event.data.get("src") or event.data.get("ip")
        if not ip or ip in self._recon_done:
            return
        self._recon_done.add(ip)
        # Auto-block only for confirmed active attackers (port scan).
        # ARP/gateway IPs are skipped — blocking the default gateway cuts connectivity.
        auto_block = event.type == EventType.PORT_SCAN
        asyncio.create_task(self._do_recon(ip, auto_block=auto_block))

    async def _do_recon(self, ip: str, auto_block: bool = False) -> None:
        from maze.utils.recon import recon_ip, format_recon
        from maze.core.events import Event, EventType, ThreatLevel
        try:
            result = await recon_ip(ip)
            await self.bus.emit(Event(
                type=EventType.RECON_RESULT,
                level=ThreatLevel.SUSPICIOUS,
                message=format_recon(result),
                data={
                    "ip": ip,
                    "hostname": result.netbios_name or result.hostname,
                    "mac": result.mac,
                    "vendor": result.vendor,
                    "open_ports": result.open_ports,
                    "banners": result.banners,
                    "os_hint": result.os_hint,
                    "netbios_name": result.netbios_name,
                },
            ))
            if auto_block:
                blocked = await self.block_ip(ip)
                if blocked:
                    await self.bus.emit(Event(
                        type=EventType.IP_BLOCKED,
                        level=ThreatLevel.DANGEROUS,
                        message=f"Auto-blocked {ip} after recon"
                                + (f" | os={result.os_hint}" if result.os_hint else "")
                                + (f" | open_ports={[p for p,_ in result.open_ports[:4]]}"
                                   if result.open_ports else ""),
                        data={"ip": ip, "mac": result.mac, "vendor": result.vendor,
                              "open_ports": result.open_ports, "os_hint": result.os_hint},
                    ))
        except Exception:
            pass

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
        return await fw.block_ip(ip) if fw else False

    async def unblock_ip(self, ip: str) -> bool:
        fw = self._fw()
        return await fw.unblock_ip(ip) if fw else False

    async def block_port(self, port: int, proto: str = "tcp") -> bool:
        fw = self._fw()
        return await fw.block_port(port, proto) if fw else False

    async def unblock_port(self, port: int, proto: str = "tcp") -> bool:
        fw = self._fw()
        return await fw.unblock_port(port, proto) if fw else False

    async def list_fw_rules(self) -> dict:
        fw = self._fw()
        return await fw.list_rules() if fw else {"ips": [], "ports_tcp": [], "ports_udp": []}

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
