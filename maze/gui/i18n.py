STRINGS: dict[str, dict[str, str]] = {
    "en": {
        # Tabs
        "tab_dashboard": "Dashboard",
        "tab_events": "Events",
        "tab_connections": "Connections",
        "tab_devices": "Devices",
        "tab_threats": "Threats",
        "tab_protection": "Protection",
        "tab_firewall": "Firewall",
        "tab_settings": "Settings",
        # Header
        "profile_label": "Profile",
        "profile_home": "Home",
        "profile_public": "Public WiFi",
        "profile_paranoid": "Paranoid",
        "profile_secure": "Secure",
        "profile_manual": "Manual",
        "theme_light": "Light",
        "theme_dark": "Dark",
        # Threat levels
        "threat_safe": "SAFE",
        "threat_suspicious": "SUSPICIOUS",
        "threat_dangerous": "DANGEROUS",
        # Table columns
        "col_time": "Time",
        "col_level": "Level",
        "col_type": "Type",
        "col_message": "Message",
        "col_pid": "PID",
        "col_process": "Process",
        "col_local": "Local",
        "col_remote": "Remote",
        "col_ip": "IP",
        "col_mac": "MAC",
        "col_hostname": "Hostname",
        "col_first_seen": "First Seen",
        "col_module": "Module",
        "col_status": "Status",
        # Module names
        "cat_detection": "Detection",
        "cat_stealth": "Stealth",
        "cat_protection": "Protection",
        "module_arp_watch": "ARP Watch",
        "module_rogue_ap": "Rogue AP Detection",
        "module_dns_validate": "DNS Validation",
        "module_tls": "TLS Monitor",
        "module_ssl_strip": "HTTPS Downgrade Detection",
        "module_hostname": "Hostname Hiding",
        "module_service_blocker": "Service Discovery Block",
        "module_fingerprint": "Fingerprint Protection",
        "module_anomaly": "Anomaly & Correlation",
        "module_fw_backend": "Firewall (firewalld)",
        "module_firewall": "Block Incoming Traffic",
        "module_port_scan": "Port Scan Detection",
        "module_process": "Process Monitor",
        "module_dns_leak": "DNS Leak Prevention",
        # Status
        "status_active": "Active",
        "status_inactive": "Inactive",
        "status_running": "Running",
        "status_stopped": "Stopped",
        "status_unavailable": "Unavailable",
        "status_working": "Working…",
        # Self-tests
        "verify_btn": "Test",
        "verify_all_btn": "Test everything",
        "verify_hint": "Test checks the system itself, not what the module "
                       "believes. Run it with a protection off and then on — "
                       "the difference between the two answers is what that "
                       "protection does.",
        "verify_running": "testing…",
        "verify_all_running": "Running every self-test, one at a time…",
        "verify_summary": "Self-test finished: {pass} in effect · "
                          "{info} nothing to enforce yet · {warn} degraded · "
                          "{fail} not in effect",
        "verify_pass": "IN EFFECT",
        "verify_fail": "NOT IN EFFECT",
        "verify_warn": "DEGRADED",
        "verify_info": "NOTHING TO ENFORCE",
        "verify_na": "NO SELF-TEST",
        "tip_verify": "Check against the system whether this is really in effect",
        "tip_verify_all": "Run every self-test and summarise what is protecting "
                          "this machine right now",
        # Firewall control
        "tip_fw_backend": "Start or stop the firewalld service itself",
        "tip_fw_shield": "Drop all unsolicited incoming traffic "
                         "(keeps allowed services working)",
        "fw_detail_zone": "zone",
        "fw_detail_rules": "block rules",
        "fw_detail_missing": "firewalld is not installed, or the "
                             "privileged helper is not running",
        "fw_detail_needs_fw": "requires the firewall to be running",
        "fw_detail_not_boot": "not enabled at boot",
        "fw_detail_panic": "PANIC MODE — all traffic dropped",
        "fw_confirm_title": "Stop the firewall?",
        "fw_confirm_body": "This stops firewalld completely. Every port on "
                           "this machine becomes reachable from the network, "
                           "and Maze Guard can no longer block attackers.\n\n"
                           "Stop it anyway?",
        "fw_msg_started": "Firewall started.",
        "fw_msg_stopped": "Firewall stopped — this host is no longer filtered.",
        "fw_msg_shield_on": "Incoming traffic is now blocked.",
        "fw_msg_shield_off": "Incoming traffic is no longer blocked.",
        "fw_msg_need_running": "Start the firewall first.",
        "fw_msg_missing": "firewalld is not available on this system.",
        "fw_msg_failed": "The firewall did not accept that change.",
        # Threats tab
        "threats_title": "Detected Attackers",
        "threats_detail": "Dossier",
        "threats_source": "Source",
        "threats_severity": "Severity",
        "threats_score": "Score",
        "threats_first_seen": "First seen",
        "threats_last_seen": "Last seen",
        "threats_identity": "IDENTITY",
        "threats_activity": "ACTIVITY",
        "threats_recon": "RECONNAISSANCE",
        "threats_after_block": "AFTER THE BLOCK",
        "threats_dropped": "Packets dropped",
        "threats_tried_ports": "Ports attempted",
        "threats_last_attempt": "Last attempt",
        "threats_actions": "ACTIONS TAKEN",
        "threats_timeline": "TIMELINE",
        "threats_techniques": "Techniques",
        "threats_packets": "Packets seen",
        "threats_ports": "Ports probed on us",
        "threats_open_ports": "Services on the source",
        "threats_findings": "Findings",
        "threats_random_mac": "MAC is randomised — identity deliberately hidden",
        "threats_tracked": "tracked",
        "threats_recent": "active in the last hour",
        "threats_blocked": "blocked",
        "threats_is_blocked": "BLOCKED",
        "threats_block": "Block",
        "threats_unblock": "Unblock",
        "threats_rescan": "Scan Source",
        "threats_scanning": "Scanning the source…",
        "threats_export": "Export Report",
        "threats_exported": "Report written to",
        "threats_export_failed": "Could not write the report.",
        "threats_block_failed": "The firewall could not block that address.",
        "threats_clear": "Clear",
        "threats_clear_confirm": "Delete every stored attacker dossier? "
                                 "The evidence journal on disk is kept.",
        "threats_empty": "No attacks recorded yet.",
        "sev_critical": "Critical",
        "sev_high": "High",
        "sev_medium": "Medium",
        "sev_low": "Low",
        "sev_info": "Info",
        "quit_shield_note": "The incoming-traffic shield is still active and "
                            "stays that way after Maze Guard closes. To lift "
                            "it, turn it off in the Protection tab before "
                            "quitting, or run:  sudo firewall-cmd --permanent "
                            "--set-target=default && sudo firewall-cmd --reload",
        # Empty states
        "no_events": "No events yet",
        "no_connections": "No active connections",
        "no_devices": "No devices detected",
        # Notifications
        "notif_danger_title": "Maze Guard — Threat Detected",
        "notif_warn_title":   "Maze Guard — Suspicious Activity",
        # Dashboard overview
        "dash_network": "Network Interface",
        "dash_firewall": "Firewall",
        "dash_threats": "Threat Status",
        "dash_open_ports": "Open Ports",
        "dash_fw_rules": "Firewall Rules",
        "dash_scan": "Scan Detection",
        "dash_ip": "IP",
        "dash_mac": "MAC",
        "dash_gateway": "Gateway",
        "dash_ssid": "Network",
        "dash_connected": "Connected",
        "dash_disconnected": "Disconnected",
        "dash_vpn": "VPN",
        "dash_fw_active": "Active",
        "dash_fw_inactive": "Inactive",
        "dash_fw_profile": "Profile",
        "dash_fw_none": "No rules",
        "dash_events_today": "events today",
        "dash_no_ports": "No listening ports",
        "dash_no_rules": "No active rules",
        "dash_blocked_ips": "Blocked IPs",
        "dash_attempts": "Scan Attempts",
        "dash_no_blocked": "None",
        "dash_scan_inactive": "Detector inactive",
        "dash_port": "Port",
        "dash_proto": "Proto",
        "dash_process": "Process",
        "dash_rule": "Rule",
        "dash_action": "Action",
        # Devices tab
        "col_vendor": "Vendor",
        "dev_info": "Info",
        "dev_scan": "Gather information",
        "dev_rescan": "Gather again",
        "dev_forget": "Forget gathered information",
        "dev_clear_all": "Forget everything gathered",
        "dev_copy_ip": "Copy IP",
        "dev_copy_mac": "Copy MAC",
        "dev_copy_report": "Copy report",
        "dev_detail_title": "DEVICE INFORMATION",
        "dev_hint": "Select a device and press Scan (or right-click it) to gather information about it.\n\n"
                    "Results are kept in memory only, and are dropped when they "
                    "age out or when you join a different network — on DHCP an "
                    "IP address is a lease, not an identity.",
        "dev_scanning": "Gathering…",
        "dev_failed": "Failed",
        "dev_ports": "ports",
        "dev_risk": "Risk",
        "dev_open_ports": "Open ports",
        "dev_no_open_ports": "No open ports found",
        "dev_random_mac": "randomised",
        "dev_gathered": "Gathered",
        "dev_ago": "ago",
        "dev_expires_in": "expires in",
        "dev_not_local": "Only devices on this network can be scanned.",
        "dev_kind": "Device type",
        "dev_name": "Name",
        "dev_model": "Model",
        "dev_description": "Description",
        "dev_scan_profile": "Scan",
        "dev_scan_all": "Gather information on all devices",
        "dev_export": "Export report…",
        "dev_export_failed": "Could not write the report.",
        "dev_profile_quick": "Quick",
        "dev_profile_standard": "Standard",
        "dev_profile_thorough": "Thorough",
        "dev_profile_quick_hint": "25 common ports, a few seconds",
        "dev_profile_standard_hint": "~100 ports with service banners and TLS",
        "dev_profile_thorough_hint": "Ports 1-1024 plus the usual suspects — minutes",
        "dev_stage_queued": "Queued…",
        "dev_stage_identity": "Resolving identity…",
        "dev_stage_ports": "Ports",
        "dev_stage_services": "Reading services…",
        "dev_stage_done": "Finishing…",
        "dev_scan_running": "The scan continues in the background; this pane "
                            "fills in when it lands.",
        "dev_partial": "Incomplete: the sweep ran out of time, so ports may be "
                       "missing from this list.",
        "dev_partial_short": "incomplete",
        "dev_known": "Known",
        "dev_known_yes": "known",
        "dev_known_no": "NEW",
        "dev_mark_known": "Mark as a known device",
        "dev_mark_unknown": "Remove the known mark",
        "dev_set_label": "Name this device…",
        "dev_label": "Name",
        "dev_search": "Filter by IP, MAC, name or type…",
        "dev_count": "devices",
        "dev_unknown_count": "unrecognised",
        "dev_learning": "learning this network…",
        "dev_history": "ON THIS NETWORK",
        "dev_first_on_network": "First seen here",
        "dev_times_seen": "Times seen",
        "dev_past_ips": "Earlier addresses",
        "dev_random_mac_note": "This device randomises its MAC address. Phones "
                               "do this by default and keep one address per "
                               "network, so it stays recognisable here.",
        "notif_new_device": "New device on your network",
        # Event explanations — what it means, and the next thing worth doing
        "explain_what": "What happened",
        "explain_why": "What it means",
        "explain_do": "What to do",
        "why_generic": "Something worth recording happened on this network.",
        "do_generic": "Look at the message above; the Threats tab has the full "
                      "record for the source involved.",
        "why_arp_spoof": "Someone on this network told your machine that they "
                         "are the router. That puts them between you and "
                         "everything you do online — this is a live "
                         "man-in-the-middle attack, not a warning about one.",
        "do_arp_spoof": "Leave this network if you can. If you cannot, use a "
                        "VPN so the traffic they relay is unreadable, and "
                        "treat anything sent in the meantime as observed.",
        "why_arp_scan": "A device is asking who else is on this network. It is "
                        "how an attacker builds a target list, and also how "
                        "some printers and network tools behave normally.",
        "do_arp_scan": "Check the Devices tab for anything you do not "
                       "recognise. On its own this is reconnaissance, not an "
                       "attack.",
        "why_rogue_ap": "A second access point is broadcasting the network name "
                        "you are connected to. Connecting to the wrong one puts "
                        "an attacker between you and the internet.",
        "do_rogue_ap": "Do not reconnect if you are dropped. Verify with "
                       "whoever runs the network before trusting it, and use a "
                       "VPN in the meantime.",
        "why_rogue_dhcp": "A second machine is handing out network settings. A "
                          "forged lease can point your gateway and DNS at the "
                          "attacker, which routes everything through them.",
        "do_rogue_dhcp": "Do not renew your lease on this network. Switch to a "
                         "network you control, or use a VPN with its own DNS.",
        "why_rogue_ra": "A second machine is advertising itself as an IPv6 "
                        "router. Your system configures itself from these "
                        "announcements, so this can silently route your IPv6 "
                        "traffic through the attacker.",
        "do_rogue_ra": "Treat it as you would a rogue DHCP server: leave the "
                       "network, or use a VPN. Disabling IPv6 also closes it, "
                       "at the cost of IPv6 connectivity.",
        "why_dns_spoof": "A DNS answer did not match what an independent "
                         "encrypted lookup returned. Someone may be sending "
                         "you to a different server than the name you asked for.",
        "do_dns_spoof": "Do not enter credentials on sites reached over this "
                        "network. Turn on encrypted DNS (DoH) in Settings, or "
                        "use a VPN.",
        "why_tls_change": "The certificate a known site presented is not the "
                          "one it presented before. Certificates do change "
                          "legitimately, but an interception proxy looks "
                          "exactly like this.",
        "do_tls_change": "If your browser also warns you, stop and leave the "
                         "site. If it does not, the site most likely rotated "
                         "its certificate.",
        "why_ssl_strip": "Traffic that should have been encrypted was seen in "
                         "plaintext, or a redirect to HTTPS went missing. That "
                         "is what an attacker does to read what you send.",
        "do_ssl_strip": "Check that the address bar still shows https:// "
                        "before typing anything sensitive, and prefer a VPN on "
                        "this network.",
        "why_port_scan": "Another device is probing your open ports one after "
                         "another — looking for a way in, or inventorying what "
                         "you run.",
        "do_port_scan": "The source is blocked automatically when auto-block is "
                        "on. Check the Threats tab to see who it was, and keep "
                        "incoming traffic blocked on untrusted networks.",
        "why_stealth_scan": "The probes carry flag combinations no ordinary "
                            "program sends. They are shaped to slip past "
                            "simple filters, which means someone is scanning "
                            "you deliberately.",
        "do_stealth_scan": "Treat this as a deliberate attack: block the "
                           "source, and raise the profile to Public or "
                           "Paranoid while you are on this network.",
        "why_host_sweep": "One device is pinging the whole network to find out "
                          "what is on it. Normal for a network scanner, "
                          "abnormal for a phone or a fridge.",
        "do_host_sweep": "Identify the source in the Devices tab. If you did "
                         "not start a scan yourself, treat it as "
                         "reconnaissance.",
        "why_anomaly": "The traffic from this source does not match how it has "
                       "behaved until now.",
        "do_anomaly": "Nothing on its own — but if the same source appears in "
                      "other alerts, take those seriously.",
        "why_attack_chain": "The same source has now done several different "
                            "hostile things. Isolated events can be noise; a "
                            "sequence is intent.",
        "do_attack_chain": "Block the source and leave the network if you can. "
                           "Export the incident report from the Threats tab if "
                           "you need to show someone.",
        "why_unknown_process": "A program on this machine opened a network "
                               "connection and is not on your known-process "
                               "list.",
        "do_unknown_process": "If you recognise it, add it to the whitelist in "
                              "Settings. If you do not, look it up before "
                              "trusting it.",
        "why_dns_leak": "A DNS query left this machine in plaintext, outside "
                        "the tunnel it was supposed to use. Whoever runs the "
                        "network can see which sites you visit.",
        "do_dns_leak": "Turn on encrypted DNS (DoH) in Settings, and check "
                       "that your VPN is configured to carry DNS.",
        "why_device_new": "A device that has never been on this network before "
                          "just joined it.",
        "do_device_new": "If you recognise it, name it and mark it known in "
                         "the Devices tab so it stops being flagged. If you do "
                         "not, scan it from there to see what it is.",
        "why_ip_moved": "An address that used to belong to one device now "
                        "answers from another, and the old one had gone quiet "
                        "first. That is how DHCP hands a freed address to the "
                        "next arrival — routine on a busy public network.",
        "do_ip_moved": "Nothing, unless it keeps happening for the same "
                       "address within seconds — that would be reported as "
                       "ARP spoofing instead.",
        "notif_new_devices_muted": "Many new devices here — further arrivals "
                                   "are logged silently (Devices tab)",
        "notif_profile_public_title": "Public network detected",
        "notif_profile_public_body": "{net}: Public profile applied — identity "
                                     "hidden, unsolicited inbound blocked. If "
                                     "this network is yours, mark it trusted "
                                     "in Settings.",
        "notif_profile_home_title": "Trusted network",
        "notif_profile_home_body": "{net}: Home profile applied.",
        "why_ip_blocked": "A firewall rule now drops everything from this "
                          "source. It stays in place until you remove it.",
        "do_ip_blocked": "Nothing is required. If it was a mistake, unblock it "
                         "from the Threats tab.",
        "why_recon_result": "This is what we found out about a source that "
                            "attacked us: what it is, and what it is running.",
        "do_recon_result": "Read it in the Threats tab, where the full dossier "
                           "and the export live.",
        # First run
        "fr_title": "Welcome to Maze Guard",
        "fr_intro": "Four questions, asked once. Everything here can be "
                    "changed later in Settings.",
        "fr_interface": "Watch this network interface:",
        "fr_trust": "Treat the current network ({network}) as trusted",
        "fr_no_network": "not detected",
        "fr_auto_block": "Block confirmed attackers automatically",
        "fr_autostart": "Start with my session, hidden in the tray",
        "fr_autostart_system": "Installed system-wide by the package; removing "
                               "it needs root.",
        "fr_note": "The security profile is chosen in the sidebar and stays "
                   "as you set it; switching it by network (trusted → Home, "
                   "anything else → Public) can be turned on in Settings. "
                   "Automatic blocking only ever "
                   "applies to confirmed attacks from devices on your own "
                   "network — never to your gateway, your DNS servers, or an "
                   "address from the internet.",
        "fr_start": "Start protecting",
    },
    "tr": {
        # Tabs
        "tab_dashboard": "Panel",
        "tab_events": "Olaylar",
        "tab_connections": "Bağlantılar",
        "tab_devices": "Cihazlar",
        "tab_threats": "Tehditler",
        "tab_protection": "Koruma",
        "tab_firewall": "Güvenlik Duvarı",
        "tab_settings": "Ayarlar",
        # Header
        "profile_label": "Profil",
        "profile_home": "Ev",
        "profile_public": "Genel WiFi",
        "profile_paranoid": "Paranoid",
        "profile_secure": "Güvenli",
        "profile_manual": "Manuel",
        "theme_light": "Açık",
        "theme_dark": "Koyu",
        # Threat levels
        "threat_safe": "GÜVENLİ",
        "threat_suspicious": "ŞÜPHELİ",
        "threat_dangerous": "TEHLİKELİ",
        # Table columns
        "col_time": "Zaman",
        "col_level": "Seviye",
        "col_type": "Tür",
        "col_message": "Mesaj",
        "col_pid": "PID",
        "col_process": "Process",
        "col_local": "Yerel",
        "col_remote": "Uzak",
        "col_ip": "IP",
        "col_mac": "MAC",
        "col_hostname": "Hostname",
        "col_first_seen": "İlk Görülme",
        "col_module": "Modül",
        "col_status": "Durum",
        # Module names
        "cat_detection": "Tespit",
        "cat_stealth": "Gizlilik",
        "cat_protection": "Koruma",
        "module_arp_watch": "ARP İzleme",
        "module_rogue_ap": "Sahte AP Tespiti",
        "module_dns_validate": "DNS Doğrulama",
        "module_tls": "TLS İzleme",
        "module_ssl_strip": "HTTPS Düşürme Tespiti",
        "module_hostname": "Hostname Gizleme",
        "module_service_blocker": "Servis Keşfi Engeli",
        "module_fingerprint": "Fingerprint Koruması",
        "module_anomaly": "Anomali ve Korelasyon",
        "module_fw_backend": "Güvenlik Duvarı (firewalld)",
        "module_firewall": "Gelen Trafiği Engelle",
        "module_port_scan": "Port Tarama Tespiti",
        "module_process": "Process İzleme",
        "module_dns_leak": "DNS Sızıntı Engeli",
        # Status
        "status_active": "Aktif",
        "status_inactive": "Pasif",
        "status_running": "Çalışıyor",
        "status_stopped": "Durdu",
        "status_unavailable": "Kullanılamıyor",
        "status_working": "İşleniyor…",
        # Kendi kendini test
        "verify_btn": "Test",
        "verify_all_btn": "Hepsini test et",
        "verify_hint": "Test, modülün kendisi hakkındaki iddiasını değil "
                       "sistemin gerçek durumunu ölçer. Bir korumayı kapalıyken "
                       "ve açıkken test et — iki cevap arasındaki fark, o "
                       "korumanın yaptığı şeydir.",
        "verify_running": "test ediliyor…",
        "verify_all_running": "Tüm testler sırayla çalışıyor…",
        "verify_summary": "Test bitti: {pass} yürürlükte · {info} uygulanacak "
                          "bir şey yok · {warn} kısıtlı · {fail} yürürlükte "
                          "değil",
        "verify_pass": "YÜRÜRLÜKTE",
        "verify_fail": "YÜRÜRLÜKTE DEĞİL",
        "verify_warn": "KISITLI",
        "verify_info": "UYGULANACAK BİR ŞEY YOK",
        "verify_na": "TESTİ YOK",
        "tip_verify": "Bunun gerçekten yürürlükte olup olmadığını sistem "
                      "üzerinden doğrula",
        "tip_verify_all": "Tüm testleri çalıştır ve bu makineyi şu anda neyin "
                          "koruduğunu özetle",
        # Firewall control
        "tip_fw_backend": "firewalld servisini başlatır veya durdurur",
        "tip_fw_shield": "İstenmeyen tüm gelen trafiği düşürür "
                         "(izin verilen servisler çalışmaya devam eder)",
        "fw_detail_zone": "bölge",
        "fw_detail_rules": "engelleme kuralı",
        "fw_detail_missing": "firewalld kurulu değil veya yetkili yardımcı "
                             "servis çalışmıyor",
        "fw_detail_needs_fw": "güvenlik duvarının çalışması gerekir",
        "fw_detail_not_boot": "açılışta başlatılmıyor",
        "fw_detail_panic": "PANİK MODU — tüm trafik düşürülüyor",
        "fw_confirm_title": "Güvenlik duvarı durdurulsun mu?",
        "fw_confirm_body": "Bu işlem firewalld'yi tamamen durdurur. Bu "
                           "makinedeki tüm portlar ağdan erişilebilir hale "
                           "gelir ve Maze Guard saldırganları engelleyemez."
                           "\n\nYine de durdurulsun mu?",
        "fw_msg_started": "Güvenlik duvarı başlatıldı.",
        "fw_msg_stopped": "Güvenlik duvarı durduruldu — bu makine artık "
                          "filtrelenmiyor.",
        "fw_msg_shield_on": "Gelen trafik artık engelleniyor.",
        "fw_msg_shield_off": "Gelen trafik engeli kaldırıldı.",
        "fw_msg_need_running": "Önce güvenlik duvarını başlatın.",
        "fw_msg_missing": "Bu sistemde firewalld bulunamadı.",
        "fw_msg_failed": "Güvenlik duvarı bu değişikliği kabul etmedi.",
        # Threats tab
        "threats_title": "Tespit Edilen Saldırganlar",
        "threats_detail": "Dosya",
        "threats_source": "Kaynak",
        "threats_severity": "Önem",
        "threats_score": "Puan",
        "threats_first_seen": "İlk görülme",
        "threats_last_seen": "Son görülme",
        "threats_identity": "KİMLİK",
        "threats_activity": "ETKİNLİK",
        "threats_recon": "KEŞİF",
        "threats_after_block": "BLOKTAN SONRA",
        "threats_dropped": "Düşürülen paket",
        "threats_tried_ports": "Denenen portlar",
        "threats_last_attempt": "Son deneme",
        "threats_actions": "ALINAN AKSİYONLAR",
        "threats_timeline": "ZAMAN ÇİZELGESİ",
        "threats_techniques": "Teknikler",
        "threats_packets": "Görülen paket",
        "threats_ports": "Bize denenen portlar",
        "threats_open_ports": "Kaynaktaki servisler",
        "threats_findings": "Bulgular",
        "threats_random_mac": "MAC rastgeleleştirilmiş — kimlik bilerek gizleniyor",
        "threats_tracked": "kayıt",
        "threats_recent": "son bir saatte aktif",
        "threats_blocked": "engellendi",
        "threats_is_blocked": "ENGELLİ",
        "threats_block": "Engelle",
        "threats_unblock": "Engeli Kaldır",
        "threats_rescan": "Kaynağı Tara",
        "threats_scanning": "Kaynak taranıyor…",
        "threats_export": "Rapor Dışa Aktar",
        "threats_exported": "Rapor yazıldı",
        "threats_export_failed": "Rapor yazılamadı.",
        "threats_block_failed": "Güvenlik duvarı bu adresi engelleyemedi.",
        "threats_clear": "Temizle",
        "threats_clear_confirm": "Kayıtlı tüm saldırgan dosyaları silinsin mi? "
                                 "Diskteki kanıt günlüğü korunur.",
        "threats_empty": "Henüz kayıtlı saldırı yok.",
        "sev_critical": "Kritik",
        "sev_high": "Yüksek",
        "sev_medium": "Orta",
        "sev_low": "Düşük",
        "sev_info": "Bilgi",
        "quit_shield_note": "Gelen trafik kalkanı hâlâ etkin ve Maze Guard "
                            "kapandıktan sonra da öyle kalacak. Kaldırmak için "
                            "çıkmadan önce Koruma sekmesinden kapatın veya şunu "
                            "çalıştırın:  sudo firewall-cmd --permanent "
                            "--set-target=default && sudo firewall-cmd --reload",
        # Empty states
        "no_events": "Henüz olay yok",
        "no_connections": "Aktif bağlantı yok",
        "no_devices": "Cihaz tespit edilmedi",
        # Notifications
        "notif_danger_title": "Maze Guard — Tehdit Tespit Edildi",
        "notif_warn_title":   "Maze Guard — Şüpheli Aktivite",
        # Dashboard overview
        "dash_network": "Ağ Arayüzü",
        "dash_firewall": "Güvenlik Duvarı",
        "dash_threats": "Tehdit Durumu",
        "dash_open_ports": "Açık Portlar",
        "dash_fw_rules": "Güvenlik Duvarı Kuralları",
        "dash_scan": "Tarama Tespiti",
        "dash_ip": "IP",
        "dash_mac": "MAC",
        "dash_gateway": "Ağ Geçidi",
        "dash_ssid": "Ağ Adı",
        "dash_connected": "Bağlı",
        "dash_disconnected": "Bağlı Değil",
        "dash_vpn": "VPN",
        "dash_fw_active": "Aktif",
        "dash_fw_inactive": "Pasif",
        "dash_fw_profile": "Profil",
        "dash_fw_none": "Kural yok",
        "dash_events_today": "olay bugün",
        "dash_no_ports": "Dinleyen port yok",
        "dash_no_rules": "Aktif kural yok",
        "dash_blocked_ips": "Engellenen IP'ler",
        "dash_attempts": "Tarama Girişimi",
        "dash_no_blocked": "Yok",
        "dash_scan_inactive": "Tespit modülü pasif",
        "dash_port": "Port",
        "dash_proto": "Protokol",
        "dash_process": "Program",
        "dash_rule": "Kural",
        "dash_action": "Aksiyon",
        # Devices tab
        "col_vendor": "Üretici",
        "dev_info": "Bilgi",
        "dev_scan": "Bilgi topla",
        "dev_rescan": "Yeniden bilgi topla",
        "dev_forget": "Toplanan bilgiyi unut",
        "dev_clear_all": "Toplanan tüm bilgileri unut",
        "dev_copy_ip": "IP'yi kopyala",
        "dev_copy_mac": "MAC'i kopyala",
        "dev_copy_report": "Raporu kopyala",
        "dev_detail_title": "CİHAZ BİLGİSİ",
        "dev_hint": "Bir cihaz hakkında bilgi toplamak için onu seçip Tara'ya basın (veya sağ tıklayın).\n\n"
                    "Sonuçlar yalnızca bellekte tutulur; süresi dolduğunda veya "
                    "başka bir ağa bağlandığınızda silinir — DHCP'de bir IP "
                    "adresi kimlik değil, kiralamadır.",
        "dev_scanning": "Toplanıyor…",
        "dev_failed": "Başarısız",
        "dev_ports": "port",
        "dev_risk": "Risk",
        "dev_open_ports": "Açık portlar",
        "dev_no_open_ports": "Açık port bulunamadı",
        "dev_random_mac": "rastgele",
        "dev_gathered": "Toplandı",
        "dev_ago": "önce",
        "dev_expires_in": "kalan süre",
        "dev_not_local": "Yalnızca bu ağdaki cihazlar taranabilir.",
        "dev_kind": "Cihaz türü",
        "dev_name": "Ad",
        "dev_model": "Model",
        "dev_description": "Açıklama",
        "dev_scan_profile": "Tarama",
        "dev_scan_all": "Tüm cihazlarda bilgi topla",
        "dev_export": "Raporu dışa aktar…",
        "dev_export_failed": "Rapor yazılamadı.",
        "dev_profile_quick": "Hızlı",
        "dev_profile_standard": "Standart",
        "dev_profile_thorough": "Detaylı",
        "dev_profile_quick_hint": "25 yaygın port, birkaç saniye",
        "dev_profile_standard_hint": "~100 port, servis banner'ları ve TLS",
        "dev_profile_thorough_hint": "1-1024 arası portlar ve fazlası — dakikalar sürer",
        "dev_stage_queued": "Sırada…",
        "dev_stage_identity": "Kimlik çözümleniyor…",
        "dev_stage_ports": "Port",
        "dev_stage_services": "Servisler okunuyor…",
        "dev_stage_done": "Tamamlanıyor…",
        "dev_scan_running": "Tarama arka planda sürüyor; bittiğinde bu panel "
                            "kendiliğinden dolacak.",
        "dev_partial": "Eksik: süpürme süre sınırına takıldı, bu listede "
                       "görünmeyen portlar olabilir.",
        "dev_partial_short": "eksik",
        "dev_known": "Bilinen",
        "dev_known_yes": "bilinen",
        "dev_known_no": "YENİ",
        "dev_mark_known": "Bilinen cihaz olarak işaretle",
        "dev_mark_unknown": "Bilinen işaretini kaldır",
        "dev_set_label": "Bu cihaza isim ver…",
        "dev_label": "İsim",
        "dev_search": "IP, MAC, isim veya türe göre filtrele…",
        "dev_count": "cihaz",
        "dev_unknown_count": "tanınmayan",
        "dev_learning": "bu ağ öğreniliyor…",
        "dev_history": "BU AĞDA",
        "dev_first_on_network": "Burada ilk görülme",
        "dev_times_seen": "Görülme sayısı",
        "dev_past_ips": "Önceki adresler",
        "dev_random_mac_note": "Bu cihaz MAC adresini rastgeleliyor. Telefonlar "
                               "bunu varsayılan olarak yapar ve her ağ için tek "
                               "bir adres kullanır, yani burada tanınır kalır.",
        "notif_new_device": "Ağında yeni bir cihaz",
        # Olay açıklamaları — ne anlama geliyor, ne yapmalı
        "explain_what": "Ne oldu",
        "explain_why": "Ne anlama geliyor",
        "explain_do": "Ne yapmalı",
        "why_generic": "Bu ağda kaydedilmeye değer bir şey oldu.",
        "do_generic": "Yukarıdaki mesaja bakın; ilgili kaynağın tam kaydı "
                      "Tehditler sekmesinde.",
        "why_arp_spoof": "Bu ağdaki biri makinenize kendisinin yönlendirici "
                         "olduğunu söyledi. Bu, sizinle internet arasına "
                         "girdiği anlamına gelir — uyarı değil, o an süren bir "
                         "ortadaki adam saldırısı.",
        "do_arp_spoof": "Mümkünse bu ağdan çıkın. Çıkamıyorsanız VPN kullanın "
                        "ki aktardıkları trafik okunamasın; o ana kadar "
                        "gönderdiklerinizi görülmüş sayın.",
        "why_arp_scan": "Bir cihaz ağda başka kim var diye soruyor. Saldırganın "
                        "hedef listesi çıkarma yöntemi budur; bazı yazıcılar "
                        "ve ağ araçları da normalde böyle davranır.",
        "do_arp_scan": "Cihazlar sekmesinde tanımadığınız bir şey var mı "
                       "bakın. Tek başına saldırı değil, keşiftir.",
        "why_rogue_ap": "Bağlı olduğunuz ağ adını yayınlayan ikinci bir erişim "
                        "noktası var. Yanlış olana bağlanmak saldırganı "
                        "sizinle internet arasına koyar.",
        "do_rogue_ap": "Bağlantınız düşerse hemen yeniden bağlanmayın. Ağı "
                       "işleteni doğrulayın, o zamana kadar VPN kullanın.",
        "why_rogue_dhcp": "İkinci bir makine ağ ayarı dağıtıyor. Sahte bir "
                          "kiralama, ağ geçidinizi ve DNS'inizi saldırgana "
                          "yönlendirebilir — yani her şey onun üzerinden akar.",
        "do_rogue_dhcp": "Bu ağda kiralamanızı yenilemeyin. Kontrol ettiğiniz "
                         "bir ağa geçin veya kendi DNS'ini taşıyan bir VPN "
                         "kullanın.",
        "why_rogue_ra": "İkinci bir makine kendisini IPv6 yönlendiricisi olarak "
                        "duyuruyor. Sisteminiz bu duyurulara göre kendini "
                        "yapılandırdığı için IPv6 trafiğiniz sessizce "
                        "saldırgan üzerinden geçebilir.",
        "do_rogue_ra": "Sahte DHCP sunucusu gibi davranın: ağdan çıkın veya VPN "
                       "kullanın. IPv6'yı kapatmak da bu yolu kapatır, ama "
                       "IPv6 bağlantınızdan olursunuz.",
        "why_dns_spoof": "Bir DNS cevabı, bağımsız şifreli sorgunun döndürdüğü "
                         "cevapla uyuşmadı. Biri sizi istediğiniz adresten "
                         "başka bir sunucuya yönlendiriyor olabilir.",
        "do_dns_spoof": "Bu ağdan eriştiğiniz sitelere parola girmeyin. "
                        "Ayarlar'dan şifreli DNS'i (DoH) açın veya VPN "
                        "kullanın.",
        "why_tls_change": "Bilinen bir sitenin sunduğu sertifika, daha önce "
                          "sunduğuyla aynı değil. Sertifikalar meşru şekilde de "
                          "değişir, ama araya giren bir vekil sunucu tam olarak "
                          "böyle görünür.",
        "do_tls_change": "Tarayıcınız da uyarıyorsa durun ve siteden çıkın. "
                         "Uyarmıyorsa site büyük ihtimalle sertifikasını "
                         "yenilemiştir.",
        "why_ssl_strip": "Şifreli olması gereken trafik düz metin görüldü ya da "
                         "HTTPS'e yönlendirme kayboldu. Saldırganın "
                         "gönderdiklerinizi okumak için yaptığı şey budur.",
        "do_ssl_strip": "Hassas bir şey yazmadan önce adres çubuğunda hâlâ "
                        "https:// olduğundan emin olun; bu ağda VPN tercih "
                        "edin.",
        "why_port_scan": "Başka bir cihaz portlarınızı tek tek yokluyor — ya "
                         "içeri girecek bir yol arıyor ya da neler "
                         "çalıştırdığınızın envanterini çıkarıyor.",
        "do_port_scan": "Otomatik engelleme açıksa kaynak zaten engellendi. "
                        "Kimin olduğunu Tehditler sekmesinden görün; güvenmediğiniz "
                        "ağlarda gelen trafiği kapalı tutun.",
        "why_stealth_scan": "Yoklamalar, hiçbir normal programın göndermediği "
                            "bayrak kombinasyonlarını taşıyor. Basit filtreleri "
                            "atlatmak için şekillendirilmişler; yani biri sizi "
                            "bilerek tarıyor.",
        "do_stealth_scan": "Bunu kasıtlı bir saldırı sayın: kaynağı engelleyin "
                           "ve bu ağdayken profili Genel veya Paranoid'e "
                           "yükseltin.",
        "why_host_sweep": "Bir cihaz, ağda ne olduğunu bulmak için herkese ping "
                          "atıyor. Bir ağ tarayıcısı için normal, bir telefon "
                          "veya buzdolabı için değil.",
        "do_host_sweep": "Kaynağı Cihazlar sekmesinde tanımlayın. Taramayı siz "
                         "başlatmadıysanız bunu keşif olarak değerlendirin.",
        "why_anomaly": "Bu kaynağın trafiği, şimdiye kadarki davranışına "
                       "uymuyor.",
        "do_anomaly": "Tek başına bir şey gerekmiyor — ama aynı kaynak başka "
                      "uyarılarda da görünüyorsa onları ciddiye alın.",
        "why_attack_chain": "Aynı kaynak artık birkaç farklı düşmanca şey yaptı. "
                            "Tek tek olaylar gürültü olabilir; sıralı olanlar "
                            "niyettir.",
        "do_attack_chain": "Kaynağı engelleyin, mümkünse ağdan çıkın. Birine "
                           "göstermeniz gerekirse Tehditler sekmesinden olay "
                           "raporunu dışa aktarın.",
        "why_unknown_process": "Bu makinedeki bir program ağ bağlantısı açtı ve "
                               "bilinen program listenizde değil.",
        "do_unknown_process": "Tanıyorsanız Ayarlar'daki beyaz listeye ekleyin. "
                              "Tanımıyorsanız güvenmeden önce araştırın.",
        "why_dns_leak": "Bir DNS sorgusu, kullanması gereken tünelin dışından, "
                        "düz metin olarak bu makineden çıktı. Ağı işleten kişi "
                        "hangi siteleri ziyaret ettiğinizi görebilir.",
        "do_dns_leak": "Ayarlar'dan şifreli DNS'i (DoH) açın ve VPN'inizin "
                       "DNS'i taşıyacak şekilde yapılandırıldığını kontrol "
                       "edin.",
        "why_device_new": "Bu ağda daha önce hiç görülmemiş bir cihaz az önce "
                          "bağlandı.",
        "do_device_new": "Tanıyorsanız Cihazlar sekmesinde isim verip bilinen "
                         "olarak işaretleyin, bir daha uyarmasın. "
                         "Tanımıyorsanız oradan tarayıp ne olduğuna bakın.",
        "why_ip_moved": "Bir cihaza ait olan adres artık başka bir cihazdan "
                        "yanıt veriyor; eskisi önce sessizleşmişti. DHCP boşa "
                        "çıkan adresi yeni gelene böyle verir — kalabalık bir "
                        "açık ağda olağan.",
        "do_ip_moved": "Hiçbir şey; aynı adres için saniyeler içinde tekrar "
                       "ederse zaten ARP sahteciliği olarak bildirilir.",
        "notif_new_devices_muted": "Bu ağda çok sayıda yeni cihaz var — "
                                   "sonrakiler sessizce kaydediliyor (Cihazlar)",
        "notif_profile_public_title": "Açık ağ algılandı",
        "notif_profile_public_body": "{net}: Açık ağ profili uygulandı — kimlik "
                                     "gizli, istenmeyen gelen bağlantılar "
                                     "engelli. Bu ağ sizinse Ayarlar'dan "
                                     "güvenilir olarak işaretleyin.",
        "notif_profile_home_title": "Güvenilir ağ",
        "notif_profile_home_body": "{net}: Ev profili uygulandı.",
        "why_ip_blocked": "Artık bir güvenlik duvarı kuralı bu kaynaktan gelen "
                          "her şeyi düşürüyor. Siz kaldırana kadar yerinde "
                          "kalır.",
        "do_ip_blocked": "Bir şey yapmanız gerekmiyor. Yanlışlıkla olduysa "
                         "Tehditler sekmesinden engeli kaldırın.",
        "why_recon_result": "Bu, bize saldıran bir kaynak hakkında "
                            "öğrendiklerimiz: ne olduğu ve ne çalıştırdığı.",
        "do_recon_result": "Tam dosya ve dışa aktarma Tehditler sekmesinde.",
        # İlk çalıştırma
        "fr_title": "Maze Guard'a hoş geldiniz",
        "fr_intro": "Bir kez sorulacak dört soru. Buradaki her şeyi sonradan "
                    "Ayarlar'dan değiştirebilirsiniz.",
        "fr_interface": "İzlenecek ağ arayüzü:",
        "fr_trust": "Şu anki ağı ({network}) güvenilir say",
        "fr_no_network": "tespit edilemedi",
        "fr_auto_block": "Doğrulanmış saldırganları otomatik engelle",
        "fr_autostart": "Oturumumla birlikte, tepside gizli başlat",
        "fr_autostart_system": "Paket tarafından sistem geneline kurulmuş; "
                               "kaldırmak için root gerekir.",
        "fr_note": "Güvenlik profili kenar çubuğundan seçilir ve siz değiştirene "
                   "kadar öyle kalır; ağa göre otomatik geçiş (güvenilir → Ev, "
                   "diğerleri → Genel) Ayarlar'dan açılabilir. Otomatik "
                   "engelleme yalnızca kendi "
                   "ağınızdaki cihazlardan gelen doğrulanmış saldırılara "
                   "uygulanır — ağ geçidinize, DNS sunucularınıza veya "
                   "internetten gelen bir adrese asla.",
        "fr_start": "Korumayı başlat",
    },
}


# ── Interface redesign (sidebar layout, overview, settings) ──────────────────
STRINGS["en"].update({
    "app_tagline": "for Maze Linux",
    "tip_reset_threat": "Reset the threat level",
    "tip_minimize": "Minimise",
    "tip_maximize": "Maximise / restore",
    "tip_close_tray": "Close to tray (keeps protecting)",
    # page subtitles
    "sub_dashboard": "Your protection status at a glance",
    "sub_threats": "Every source that has attacked this machine, and what we know about it",
    "sub_events": "Everything the detectors have reported this session",
    "sub_devices": "Who else is on this network",
    "sub_connections": "Which programs are talking to the internet right now",
    "sub_protection": "Turn protections on or off, and test that they really work",
    "sub_firewall": "Addresses, devices and ports that are being dropped",
    "sub_settings": "Preferences, profiles and lists",
    # overview
    "hero_ok_title": "You are protected",
    "hero_ok_body": "{active} of {total} protections are active on {network}. Nothing needs your attention.",
    "hero_warn_title": "Something is worth a look",
    "hero_warn_body": "Suspicious activity was seen on {network}. It is not a confirmed attack, but the events explain what happened.",
    "hero_warn_action": "View events",
    "hero_danger_title": "Attack detected",
    "hero_danger_body": "Dangerous activity was detected on {network}. Review what happened and decide whether to block the source.",
    "hero_danger_action": "Review threats",
    "hero_limited_title": "Limited mode",
    "hero_limited_body": "The privileged helper is not running, so the firewall cannot be managed and packet capture is unavailable. Start it with: sudo systemctl enable --now maze-guard.service",
    "hero_limited_action": "Details",
    "hero_fw_off_title": "The firewall is stopped",
    "hero_fw_off_body": "Nothing on this machine is being filtered and blocks cannot be applied.",
    "hero_fw_off_action": "Open protection",
    "tile_threats": "Active threats (1 h)",
    "tile_blocked": "Blocked sources",
    "tile_devices": "Devices on network",
    "tile_events": "Events this session",
    "dash_protection": "Protection",
    "dash_manage": "Manage",
    "dash_recent": "Recent alerts",
    "dash_recent_empty": "No alerts this session.",
    "dash_view_all": "All events",
    "dash_iface": "Interface",
    "dash_traffic": "Traffic",
    "dash_wired": "Wired network",
    "threats_select_hint": "Select a source to see everything known about it.",
    "dash_helper": "Privileged helper",
    "dash_helper_ok": "Connected",
    "dash_helper_missing": "Not running",
    "dash_modules": "Protections",
    "dash_modules_fmt": "{active} of {total} active",
    "dash_rules_fmt": "{n} drop rules",
    "dash_scope": "Reachable from",
    "dash_scope_local": "This machine",
    "dash_scope_network": "Network",
    "dash_ports_hint": "Services listening for connections. {n} can be reached from the network — right-click one to block it.",
    "dash_block_port": "Block port {port}",
    # protection page descriptions
    "desc_arp_watch": "Spots another device impersonating your router (ARP spoofing / man-in-the-middle).",
    "desc_rogue_ap": "Warns when a second access point copies your Wi-Fi network's name (evil twin).",
    "desc_dns_validate": "Cross-checks DNS answers against encrypted resolvers to catch tampering.",
    "desc_tls": "Remembers the certificates of well-known sites and flags unexpected changes.",
    "desc_ssl_strip": "Notices when a site that supports HTTPS is suddenly reached over plain HTTP.",
    "desc_anomaly": "Links separate events together to recognise multi-step attacks.",
    "desc_hostname": "Stops announcing this computer's name on the network (mDNS).",
    "desc_service_blocker": "Closes discovery ports (mDNS, NetBIOS, SSDP, SMB) to strangers.",
    "desc_fingerprint": "Makes it harder to tell which operating system this machine runs.",
    "desc_fw_backend": "The system firewall (firewalld) that every block relies on.",
    "desc_firewall": "Drops unsolicited incoming connections while allowed services keep working.",
    "desc_port_scan": "Detects devices probing this machine's ports.",
    "desc_process": "Reports programs that open network connections and are not on your trusted list.",
    "desc_dns_leak": "Detects DNS queries escaping a VPN tunnel.",
    # events page
    "ev_all": "All",
    "ev_search": "Search events…",
    "ev_count": "{shown} of {total}",
    "ev_export": "Export CSV",
    "ev_export_tip": "Save the events currently shown to a CSV file",
    "ev_clear": "Clear",
    "ev_empty": "No events yet. Detections will appear here as they happen.",
    "ev_select_hint": "Select an event to see what it means and what to do about it.",
    "ev_copy": "Copy message",
    "ev_block_ip": "Block {ip}",
    # connections page
    "conn_search": "Filter by program, address or service…",
    "conn_only_unknown": "Only untrusted programs",
    "conn_count": "{shown} shown · {total} connections · {unknown} untrusted",
    "conn_empty": "No connections to show. The list fills while the Process Monitor can read connection data.",
    "conn_known": "Trusted",
    "conn_unknown": "Untrusted",
    "conn_service": "Service",
    "conn_status": "Status",
    "conn_copy_remote": "Copy remote address",
    # devices page
    "dev_btn_scan": "Scan",
    "dev_btn_rescan": "Rescan",
    "dev_btn_scan_all": "Scan all",
    "dev_empty": "No devices seen yet. Devices appear as ARP Watch notices them on the network.",
    # firewall page
    "fwv_sources": "Blocked addresses and devices",
    "fwv_sources_hint": "Traffic from these is dropped. Device (MAC) blocks survive the attacker changing IP address.",
    "fwv_ports": "Blocked ports",
    "fwv_ports_hint": "Incoming connections to these ports are dropped, over IPv4 and IPv6.",
    "fwv_sources_empty": "Nothing is blocked.",
    "fwv_ports_empty": "No ports are blocked.",
    "fwv_address": "Address",
    "fwv_kind": "Type",
    "fwv_kind_ip": "IP",
    "fwv_kind_mac": "Device",
    "fwv_unblock": "Unblock",
    "fwv_block": "Block",
    "fwv_clear": "Remove all rules",
    "fwv_clear_confirm": "Remove every address, device and port block?\n\nBlocked attackers will be able to reach this machine again.",
    "fwv_cleared": "All rules removed",
    "fwv_ip_placeholder": "IP or range, e.g. 192.168.1.99, 10.0.0.0/24, fe80::1",
    "fwv_port_placeholder": "Port, e.g. 22",
    "fwv_invalid_ip": "Not an IP address or range: {ip}",
    "fwv_too_broad": "Range too broad (it would cut this machine off): {ip}",
    "fwv_invalid_port": "Enter a port between 1 and 65535",
    "fwv_blocked": "Blocked {what}",
    "fwv_unblocked": "Unblocked {what}",
    "fwv_failed": "Could not change the rule for {what}",
    "fwv_backend_missing": "firewalld unavailable",
    # settings
    "set_appearance": "Appearance",
    "set_language": "Language",
    "set_theme": "Theme",
    "set_response": "Alerts and response",
    "set_notify": "Desktop notifications",
    "set_notify_dangerous": "Dangerous only (recommended)",
    "set_notify_suspicious": "Dangerous and suspicious",
    "set_notify_off": "Off — show in the app only",
    "set_threshold": "Port-scan sensitivity",
    "set_threshold_tip": "How many probed ports from one source count as a scan. Lower is more sensitive.",
    "set_notify_new_devices": "Notify me when an unknown device joins my network",
    "set_auto_block": "Automatically block confirmed attackers",
    "set_auto_block_tip": "A source caught scanning this machine gets a firewall drop rule.\nGateway, DNS and whitelisted addresses are never blocked, and internet (spoofable) sources are ignored.",
    "set_block_by_mac": "Also block the attacker's device (MAC address)",
    "set_block_by_mac_tip": "An IP block is avoided by renewing the address; a device block is not. Only meaningful on the local network.",
    "set_profiles": "Custom profiles",
    "set_profiles_hint": "Your own combinations of protections. They appear in the profile selector in the sidebar.",
    "set_profile_new": "New profile…",
    "set_profile_edit": "Edit",
    "set_profile_delete": "Delete",
    "set_profile_delete_confirm": "Delete the profile \"{name}\"?",
    "set_auto_profile": "Switch profile by network",
    "set_auto_profile_cb": "Use Home on trusted networks and Public Wi-Fi everywhere else",
    "set_auto_profile_hint": "Off by default. When on, it replaces the profile you picked whenever the network changes.",
    "set_trust_current": "Trust current network",
    "set_no_network": "No network detected",
    "set_trusted_ok": "Trusted: {net}",
    "set_whitelist": "Ignored addresses",
    "set_whitelist_hint": "Detectors never report or block these. Single addresses or ranges (CIDR), IPv4 or IPv6.",
    "set_whitelist_placeholder": "e.g. 192.168.1.10 or 10.0.0.0/8",
    "set_processes": "Trusted programs",
    "set_processes_hint": "Programs allowed to make network connections without being reported.",
    "set_process_placeholder": "Program name, e.g. vlc",
    "set_filter": "Filter…",
    "set_add": "Add",
    "set_remove": "Remove",
    "set_system": "System",
    "set_autostart": "Start with my session, hidden in the tray",
    "set_autostart_system": "The package also starts Maze Guard for every user ({path}); removing that needs root.",
    "set_config_file": "Settings file",
    # profile dialog
    "pf_title_new": "New profile",
    "pf_title_edit": "Edit profile",
    "pf_name": "Name",
    "pf_name_placeholder": "e.g. Office, Coffee shop",
    "pf_name_required": "Enter a name.",
    "pf_name_taken": "A profile with this name already exists.",
    "pf_note": "Passive detection (ARP, rogue AP, TLS, HTTPS downgrade, DNS leak) is always on. Choose what else this profile turns on:",
    "pf_port_scan_detect": "Port scan detection",
    "pf_process_monitor": "Untrusted program monitoring",
    "pf_doh_enabled": "DNS validation",
    "pf_block_incoming": "Block unsolicited incoming traffic",
    "pf_hide_hostname": "Hide hostname (mDNS)",
    "pf_fingerprint_protect": "Fingerprint protection",
    "pf_block_services": "Block discovery services (mDNS, NetBIOS, SMB…)",
    "pf_save": "Save",
    "pf_cancel": "Cancel",
    # quit summary
    "sum_title": "Session summary",
    "sum_total": "Total events",
})

STRINGS["tr"].update({
    "app_tagline": "Maze Linux için",
    "tip_reset_threat": "Tehdit seviyesini sıfırla",
    "tip_minimize": "Simge durumuna küçült",
    "tip_maximize": "Büyüt / geri yükle",
    "tip_close_tray": "Tepsiye kapat (korumaya devam eder)",
    "sub_dashboard": "Koruma durumunuz tek bakışta",
    "sub_threats": "Bu makineye saldıran her kaynak ve onun hakkında bildiklerimiz",
    "sub_events": "Bu oturumda dedektörlerin bildirdiği her şey",
    "sub_devices": "Bu ağda başka kimler var",
    "sub_connections": "Şu anda hangi programlar internetle konuşuyor",
    "sub_protection": "Korumaları açın/kapatın ve gerçekten çalıştıklarını test edin",
    "sub_firewall": "Engellenen adresler, cihazlar ve portlar",
    "sub_settings": "Tercihler, profiller ve listeler",
    "hero_ok_title": "Korunuyorsunuz",
    "hero_ok_body": "{network} ağında {total} korumadan {active} tanesi etkin. İlgilenmeniz gereken bir şey yok.",
    "hero_warn_title": "Göz atmaya değer bir şey var",
    "hero_warn_body": "{network} ağında şüpheli etkinlik görüldü. Doğrulanmış bir saldırı değil; olaylar ne olduğunu açıklıyor.",
    "hero_warn_action": "Olayları gör",
    "hero_danger_title": "Saldırı tespit edildi",
    "hero_danger_body": "{network} ağında tehlikeli etkinlik tespit edildi. Ne olduğunu inceleyip kaynağı engellemeye karar verin.",
    "hero_danger_action": "Tehditleri incele",
    "hero_limited_title": "Sınırlı mod",
    "hero_limited_body": "Yetkili yardımcı servis çalışmıyor; güvenlik duvarı yönetilemiyor ve paket yakalama kullanılamıyor. Başlatmak için: sudo systemctl enable --now maze-guard.service",
    "hero_limited_action": "Ayrıntılar",
    "hero_fw_off_title": "Güvenlik duvarı durdurulmuş",
    "hero_fw_off_body": "Bu makinede hiçbir trafik filtrelenmiyor ve engelleme uygulanamıyor.",
    "hero_fw_off_action": "Korumayı aç",
    "tile_threats": "Aktif tehdit (1 sa)",
    "tile_blocked": "Engellenen kaynak",
    "tile_devices": "Ağdaki cihaz",
    "tile_events": "Bu oturumdaki olay",
    "dash_protection": "Koruma",
    "dash_manage": "Yönet",
    "dash_recent": "Son uyarılar",
    "dash_recent_empty": "Bu oturumda uyarı yok.",
    "dash_view_all": "Tüm olaylar",
    "dash_iface": "Arayüz",
    "dash_traffic": "Trafik",
    "dash_wired": "Kablolu ağ",
    "threats_select_hint": "Hakkında bilinen her şeyi görmek için bir kaynak seçin.",
    "dash_helper": "Yetkili yardımcı",
    "dash_helper_ok": "Bağlı",
    "dash_helper_missing": "Çalışmıyor",
    "dash_modules": "Korumalar",
    "dash_modules_fmt": "{total} korumadan {active} etkin",
    "dash_rules_fmt": "{n} engelleme kuralı",
    "dash_scope": "Erişilebilir",
    "dash_scope_local": "Yalnızca bu makine",
    "dash_scope_network": "Ağdan",
    "dash_ports_hint": "Bağlantı bekleyen servisler. {n} tanesine ağdan erişilebiliyor — engellemek için sağ tıklayın.",
    "dash_block_port": "{port} portunu engelle",
    "desc_arp_watch": "Başka bir cihazın modeminizi taklit etmesini (ARP sahteciliği / ortadaki adam) yakalar.",
    "desc_rogue_ap": "Wi-Fi ağınızın adını kopyalayan ikinci bir erişim noktasını (kötü ikiz) bildirir.",
    "desc_dns_validate": "DNS yanıtlarını şifreli çözümleyicilerle karşılaştırıp kurcalamayı yakalar.",
    "desc_tls": "Bilinen sitelerin sertifikalarını hatırlar, beklenmedik değişiklikleri işaretler.",
    "desc_ssl_strip": "HTTPS destekleyen bir siteye birden düz HTTP ile gidildiğini fark eder.",
    "desc_anomaly": "Ayrı olayları birbirine bağlayarak çok adımlı saldırıları tanır.",
    "desc_hostname": "Bu bilgisayarın adını ağda duyurmayı (mDNS) durdurur.",
    "desc_service_blocker": "Keşif portlarını (mDNS, NetBIOS, SSDP, SMB) yabancılara kapatır.",
    "desc_fingerprint": "Bu makinenin hangi işletim sistemini çalıştırdığını anlamayı zorlaştırır.",
    "desc_fw_backend": "Tüm engellemelerin dayandığı sistem güvenlik duvarı (firewalld).",
    "desc_firewall": "İzin verilen servisler çalışmaya devam ederken istenmeyen gelen bağlantıları düşürür.",
    "desc_port_scan": "Bu makinenin portlarını yoklayan cihazları tespit eder.",
    "desc_process": "Güvenilir listenizde olmayan ve ağ bağlantısı açan programları bildirir.",
    "desc_dns_leak": "VPN tünelinden kaçan DNS sorgularını tespit eder.",
    "ev_all": "Tümü",
    "ev_search": "Olaylarda ara…",
    "ev_count": "{shown} / {total}",
    "ev_export": "CSV olarak dışa aktar",
    "ev_export_tip": "Şu an görünen olayları bir CSV dosyasına kaydet",
    "ev_clear": "Temizle",
    "ev_empty": "Henüz olay yok. Tespitler oldukça burada görünür.",
    "ev_select_hint": "Ne anlama geldiğini ve ne yapmanız gerektiğini görmek için bir olay seçin.",
    "ev_copy": "Mesajı kopyala",
    "ev_block_ip": "{ip} adresini engelle",
    "conn_search": "Program, adres veya servise göre filtrele…",
    "conn_only_unknown": "Yalnızca güvenilmeyen programlar",
    "conn_count": "{shown} gösteriliyor · {total} bağlantı · {unknown} güvenilmeyen",
    "conn_empty": "Gösterilecek bağlantı yok. Liste, İşlem İzleyici bağlantı verisini okuyabildiğinde dolar.",
    "conn_known": "Güvenilir",
    "conn_unknown": "Güvenilmeyen",
    "conn_service": "Servis",
    "conn_status": "Durum",
    "conn_copy_remote": "Uzak adresi kopyala",
    "dev_btn_scan": "Tara",
    "dev_btn_rescan": "Yeniden tara",
    "dev_btn_scan_all": "Tümünü tara",
    "dev_empty": "Henüz cihaz görülmedi. ARP İzleme ağda fark ettikçe cihazlar burada görünür.",
    "fwv_sources": "Engellenen adresler ve cihazlar",
    "fwv_sources_hint": "Bunlardan gelen trafik düşürülür. Cihaz (MAC) engeli, saldırgan IP değiştirse de geçerli kalır.",
    "fwv_ports": "Engellenen portlar",
    "fwv_ports_hint": "Bu portlara gelen bağlantılar IPv4 ve IPv6 üzerinden düşürülür.",
    "fwv_sources_empty": "Engellenen bir şey yok.",
    "fwv_ports_empty": "Engellenen port yok.",
    "fwv_address": "Adres",
    "fwv_kind": "Tür",
    "fwv_kind_ip": "IP adresi",
    "fwv_kind_mac": "Cihaz",
    "fwv_unblock": "Engeli kaldır",
    "fwv_block": "Engelle",
    "fwv_clear": "Tüm kuralları kaldır",
    "fwv_clear_confirm": "Tüm adres, cihaz ve port engelleri kaldırılsın mı?\n\nEngellenen saldırganlar bu makineye yeniden erişebilir.",
    "fwv_cleared": "Tüm kurallar kaldırıldı",
    "fwv_ip_placeholder": "IP veya aralık, ör. 192.168.1.99, 10.0.0.0/24, fe80::1",
    "fwv_port_placeholder": "Port, ör. 22",
    "fwv_invalid_ip": "Geçerli bir IP adresi veya aralığı değil: {ip}",
    "fwv_too_broad": "Aralık çok geniş (bu makinenin bağlantısını keser): {ip}",
    "fwv_invalid_port": "1 ile 65535 arasında bir port girin",
    "fwv_blocked": "{what} engellendi",
    "fwv_unblocked": "{what} engeli kaldırıldı",
    "fwv_failed": "{what} için kural değiştirilemedi",
    "fwv_backend_missing": "firewalld kullanılamıyor",
    "set_appearance": "Görünüm",
    "set_language": "Dil",
    "set_theme": "Tema",
    "set_response": "Uyarılar ve tepki",
    "set_notify": "Masaüstü bildirimleri",
    "set_notify_dangerous": "Yalnızca tehlikeli (önerilen)",
    "set_notify_suspicious": "Tehlikeli ve şüpheli",
    "set_notify_off": "Kapalı — yalnızca uygulamada göster",
    "set_threshold": "Port taraması hassasiyeti",
    "set_threshold_tip": "Tek bir kaynaktan kaç port yoklanırsa tarama sayılacağı. Düşük değer daha hassastır.",
    "set_notify_new_devices": "Ağıma bilinmeyen bir cihaz katıldığında bildir",
    "set_auto_block": "Doğrulanmış saldırganları otomatik engelle",
    "set_auto_block_tip": "Bu makineyi tararken yakalanan kaynağa bir güvenlik duvarı engeli eklenir.\nAğ geçidi, DNS ve yok sayılan adresler asla engellenmez; internetten (sahtelenebilir) gelen kaynaklar dikkate alınmaz.",
    "set_block_by_mac": "Saldırganın cihazını da (MAC adresi) engelle",
    "set_block_by_mac_tip": "IP engelinden adres yenilenerek kaçılabilir; cihaz engelinden kaçılamaz. Yalnızca yerel ağda anlamlıdır.",
    "set_profiles": "Özel profiller",
    "set_profiles_hint": "Kendi koruma kombinasyonlarınız. Kenar çubuğundaki profil seçicide görünürler.",
    "set_profile_new": "Yeni profil…",
    "set_profile_edit": "Düzenle",
    "set_profile_delete": "Sil",
    "set_profile_delete_confirm": "\"{name}\" profili silinsin mi?",
    "set_auto_profile": "Ağa göre profil değiştir",
    "set_auto_profile_cb": "Güvenilir ağlarda Ev, diğer her yerde Açık Wi-Fi profilini kullan",
    "set_auto_profile_hint": "Varsayılan olarak kapalı. Açıkken, ağ her değiştiğinde seçtiğiniz profilin yerine geçer.",
    "set_trust_current": "Şu anki ağa güven",
    "set_no_network": "Ağ tespit edilemedi",
    "set_trusted_ok": "Güvenilir: {net}",
    "set_whitelist": "Yok sayılan adresler",
    "set_whitelist_hint": "Dedektörler bunları asla bildirmez veya engellemez. Tek adres ya da aralık (CIDR), IPv4 veya IPv6.",
    "set_whitelist_placeholder": "ör. 192.168.1.10 veya 10.0.0.0/8",
    "set_processes": "Güvenilir programlar",
    "set_processes_hint": "Bildirilmeden ağ bağlantısı kurmasına izin verilen programlar.",
    "set_process_placeholder": "Program adı, ör. vlc",
    "set_filter": "Filtrele…",
    "set_add": "Ekle",
    "set_remove": "Kaldır",
    "set_system": "Sistem",
    "set_autostart": "Oturumumla birlikte, tepside gizli başlat",
    "set_autostart_system": "Paket Maze Guard'ı tüm kullanıcılar için de başlatıyor ({path}); bunu kaldırmak root gerektirir.",
    "set_config_file": "Ayar dosyası",
    "pf_title_new": "Yeni profil",
    "pf_title_edit": "Profili düzenle",
    "pf_name": "Ad",
    "pf_name_placeholder": "ör. Ofis, Kafe",
    "pf_name_required": "Bir ad girin.",
    "pf_name_taken": "Bu adda bir profil zaten var.",
    "pf_note": "Pasif tespit (ARP, sahte erişim noktası, TLS, HTTPS düşürme, DNS sızıntısı) her zaman açıktır. Bu profilin başka neyi açacağını seçin:",
    "pf_port_scan_detect": "Port taraması tespiti",
    "pf_process_monitor": "Güvenilmeyen program izleme",
    "pf_doh_enabled": "DNS doğrulama",
    "pf_block_incoming": "İstenmeyen gelen trafiği engelle",
    "pf_hide_hostname": "Bilgisayar adını gizle (mDNS)",
    "pf_fingerprint_protect": "Parmak izi koruması",
    "pf_block_services": "Keşif servislerini engelle (mDNS, NetBIOS, SMB…)",
    "pf_save": "Kaydet",
    "pf_cancel": "İptal",
    "sum_title": "Oturum özeti",
    "sum_total": "Toplam olay",
})


# Event type names, and tray / shortcut strings.
STRINGS["en"].update({
    "evtype_arp_spoof": "ARP spoofing",
    "evtype_ip_moved": "Address reassigned",
    "evtype_arp_scan": "ARP sweep",
    "evtype_rogue_ap": "Rogue access point",
    "evtype_rogue_dhcp": "Rogue DHCP server",
    "evtype_rogue_ra": "Rogue IPv6 router",
    "evtype_dns_spoof": "DNS tampering",
    "evtype_tls_change": "Certificate change",
    "evtype_ssl_strip": "HTTPS downgrade",
    "evtype_port_scan": "Port scan",
    "evtype_stealth_scan": "Stealth scan",
    "evtype_host_sweep": "Host sweep",
    "evtype_anomaly": "Anomaly",
    "evtype_attack_chain": "Attack chain",
    "evtype_unknown_process": "Untrusted program",
    "evtype_dns_leak": "DNS leak",
    "evtype_profile_changed": "Profile changed",
    "evtype_device_found": "Device seen",
    "evtype_device_new": "New device",
    "evtype_module_toggled": "Protection toggled",
    "evtype_engine_ready": "Started",
    "evtype_recon_result": "Source profile",
    "evtype_ip_blocked": "Blocked",
    "evtype_firewall_changed": "Firewall changed",
    "tray_open": "Open Maze Guard",
    "tray_profile": "Profile",
    "tray_quit": "Quit",
    "tray_tooltip": "Maze Guard — status: {level}",
    "threats_copy_ip": "Copy address",
    "notif_title_danger": "Threat: {kind}",
    "notif_title_warn": "Suspicious: {kind}",
    "notif_title_blocked": "Attack blocked: {kind}",
    "notif_blocked_body": "Maze Guard blocked the source automatically.",
    "hero_outdated_title": "The helper service is out of date",
    "hero_outdated_body": "It is older than this window and is missing fixes it relies on. Restart it: sudo systemctl restart maze-guard.service — or reinstall the package.",
    "hero_outdated_action": "Details",
    "set_helper_outdated": "Connected, but out of date — restart it",
    "ago_s": "{n}s ago",
    "ago_m": "{n}m ago",
    "ago_h": "{n}h ago",
    "ago_d": "{n}d ago",
    "ev_open_threat": "Open in Threats",
})

STRINGS["tr"].update({
    "evtype_arp_spoof": "ARP sahteciliği",
    "evtype_ip_moved": "Adres el değiştirdi",
    "evtype_arp_scan": "ARP taraması",
    "evtype_rogue_ap": "Sahte erişim noktası",
    "evtype_rogue_dhcp": "Sahte DHCP sunucusu",
    "evtype_rogue_ra": "Sahte IPv6 yönlendirici",
    "evtype_dns_spoof": "DNS kurcalama",
    "evtype_tls_change": "Sertifika değişti",
    "evtype_ssl_strip": "HTTPS düşürme",
    "evtype_port_scan": "Port taraması",
    "evtype_stealth_scan": "Gizli tarama",
    "evtype_host_sweep": "Ağ taraması",
    "evtype_anomaly": "Anormallik",
    "evtype_attack_chain": "Saldırı zinciri",
    "evtype_unknown_process": "Güvenilmeyen program",
    "evtype_dns_leak": "DNS sızıntısı",
    "evtype_profile_changed": "Profil değişti",
    "evtype_device_found": "Cihaz görüldü",
    "evtype_device_new": "Yeni cihaz",
    "evtype_module_toggled": "Koruma değişti",
    "evtype_engine_ready": "Başlatıldı",
    "evtype_recon_result": "Kaynak profili",
    "evtype_ip_blocked": "Engellendi",
    "evtype_firewall_changed": "Güvenlik duvarı değişti",
    "tray_open": "Maze Guard'ı aç",
    "tray_profile": "Profil",
    "tray_quit": "Çıkış",
    "tray_tooltip": "Maze Guard — durum: {level}",
    "threats_copy_ip": "Adresi kopyala",
    "notif_title_danger": "Tehdit: {kind}",
    "notif_title_warn": "Şüpheli: {kind}",
    "notif_title_blocked": "Saldırı engellendi: {kind}",
    "notif_blocked_body": "Maze Guard kaynağı otomatik olarak engelledi.",
    "hero_outdated_title": "Yardımcı servis güncel değil",
    "hero_outdated_body": "Bu pencereden eski ve dayandığı düzeltmeler eksik. Yeniden başlatın: sudo systemctl restart maze-guard.service — veya paketi yeniden kurun.",
    "hero_outdated_action": "Ayrıntılar",
    "set_helper_outdated": "Bağlı ama güncel değil — yeniden başlatın",
    "ago_s": "{n} sn önce",
    "ago_m": "{n} dk önce",
    "ago_h": "{n} sa önce",
    "ago_d": "{n} gün önce",
    "ev_open_threat": "Tehditler'de aç",
})


def t(key: str, lang: str = "en") -> str:
    return STRINGS.get(lang, STRINGS["en"]).get(key, key)
