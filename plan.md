Çok daha net ve gerçekçi bir kullanım senaryosu. Kafe WiFi'ı, havalimanı ağı, otel interneti — bunlarda kullanıcıyı koruyan bir araç.

---

## Asıl Problem Ne?

Public ağda seni tehdit eden 3 şey var:

```
1. Ağ içi saldırılar
   ARP spoofing, MITM, rogue AP, DNS poisoning
   → saldırgan senin trafiğini okur/değiştirir

2. Ağ içi takip
   MAC adresiyle cihaz tanımlama
   mDNS/NetBIOS ile hostname yayınlama
   Passive fingerprinting (OS, browser, servisler)

3. Dışarıya açık yüzey
   Gereksiz açık portlar
   Firewall kuralı olmayan servisler
   Bilinmeyen outbound bağlantılar
```

---

## Konsept: **Maze Guard**

> *"Public ağa bağlandığın anda devreye girer. Saldırıları tespit eder, cihazını izole eder, ağda iz bırakmazsın."*

---

## Ne Yapar?

### 🔍 MITM & Saldırı Tespiti
```
ARP Watch
  → ağdaki ARP trafiğini dinle (scapy)
  → gateway MAC değişirse → anında uyar + bağlantıyı kes seçeneği
  → ARP poisoning pattern'i tespit et

Rogue Access Point
  → bağlı olduğun SSID'yi kaydet (BSSID + sinyal)
  → aynı SSID farklı BSSID'den gelirse → Evil Twin uyarısı

DNS Doğrulama
  → her DNS cevabını 2-3 farklı DoH resolver ile karşılaştır
     (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9)
  → cevaplar uyuşmazsa → DNS spoofing uyarısı

TLS Sertifika İzleme
  → düzenli ziyaret ettiğin sitelerin sertifika hash'ini kaydet
  → değişirse → MITM şüphesi bildirimi

SSL Strip Tespiti
  → HTTPS redirect yerine HTTP cevabı gelirse → uyar
```

### 🕵️ Ağ İçi Takipi Engelleme
```
MAC Randomization
  → her yeni ağa bağlanmada MAC otomatik değişir
  → zamanlayıcı ile periyodik rotasyon (örn. her 30 dk)
  → bağlantı kesilmeden değişim (NetworkManager entegrasyonu)

Hostname Gizleme
  → mDNS (Avahi) yayınını durdur
  → NetBIOS name broadcast'i kapat
  → DHCP hostname alanını rastgele veya boş gönder

Servis Keşfini Engelle
  → dışarıya açık dinleme portlarını tespit et
  → "Gizle" → o porta gelen bağlantıları drop et (nftables)

Passive OS Fingerprint Koruması
  → TCP/IP stack parametrelerini normalize et
     (TTL, window size, TCP options)
  → p0f veya nmap'in cihazı tanımasını zorlaştır
```

### 🛡️ Cihaz Koruma
```
Firewall Otomasyonu
  → "Public Ağ" profili aktifleşince preset kurallar devreye girer
  → gelen tüm bağlantılar drop, sadece kurulu oturumlar geçer
  → outbound: sadece 80/443/53 izinli (isteğe göre)

Port Tarama Tespiti
  → SYN flood, port scan pattern'i tespit et (portsentry mantığı)
  → tarayana otomatik kural ekle → drop

Process → Ağ Haritası
  → hangi process nereye bağlanıyor (/proc/net + ss)
  → bilinmeyen process dış IP'ye bağlanırsa → uyar

DNS Sızıntısı Engelleme
  → tüm DNS trafiğini DNS-over-HTTPS'e yönlendir
  → plain UDP 53 sorgularını iptables ile kes
  → sistemdeki tüm resolver'ları override et (/etc/resolv.conf)
```

### 📊 Gerçek Zamanlı Dashboard
```
Ağ Tehdit Seviyesi  → Güvenli / Şüpheli / Tehlikeli
Aktif tehditler     → zaman damgalı olay listesi
Bağlantı haritası   → process + hedef IP + port + bayrak
Cihaz listesi       → ağdaki diğer cihazlar (pasif ARP)
Koruma durumu       → hangi modüller aktif/pasif
```

---

## Çalışma Modu

```
Manuel mod
  → kullanıcı her modülü ayrı ayrı açar/kapar

Profil modu
  → "Ev" → sadece temel izleme
  → "Public WiFi" → her şey maksimum, MAC randomize, mDNS kapalı
  → "Paranoid" → gelen tüm trafik drop, sadece whitelist outbound

Otomatik tetikleme
  → NetworkManager hook → ağ tipi değişince profil otomatik değişir
  → "Bilmediğim bir ağa bağlandım" → anında Public profil
```

---

## Stack

| Katman | Teknoloji |
|---|---|
| Paket yakalama | `scapy` |
| DNS doğrulama | `httpx` (DoH) |
| Firewall | `nftables` (python-nftables) |
| NetworkManager | `dbus-python` |
| MAC değiştirme | `iproute2` / `ip link` subprocess |
| Process-network map | `/proc/net/tcp` + `/proc/PID/fd` |
| GUI | `PyQt6` + `qasync` |
| Bildirim | `libnotify` / system tray |

---

## Portföyüne Katkısı

Şu an portföyün tamamen **Tor + E2E + chat/file** üzerine. Bu proje farklı bir alan açıyor:

```
sentinai      → offensive OSINT
haze          → iletişim güvenliği
hazedrop      → dosya güvenliği
entropy-shield→ sistem privacy stack
NetCloak      → ağ güvenliği + cihaz koruması  ← YENİ ALAN
```

Hacker topluluğunda "public WiFi'da ne yapmalı" sorusu çok sorulur ama bunu GUI'dan yöneten, otomatik tespit yapan **paket halinde** bir Linux aracı gerçekten az. Spec yazayım mı?
