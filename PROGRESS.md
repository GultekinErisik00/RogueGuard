# RogueGuard — İlerleme

## Oturum 1 — 15 Kasım 2026

### Durum
- [x] VM ayakta: `rogueguard-lab`, Ubuntu 26.10, 4 çekirdek, 9.2 GiB RAM, `enp2s0` = 192.168.23.136/24 (Fusion NAT 192.168.23.0/24)
- [x] `ssh rogue` çalışıyor
- [ ] Şifresiz sudo **yok** → kullanıcıdan `/etc/sudoers.d/rogue` istendi
- [ ] Kök bölüm 28 GB (LVM'de boş alan var, `lvextend` bekliyor, sudo gerekli)
- [x] Swap: kurulumdan gelen 4 GB `/swap.img` var → ayrı `/swapfile` gerekmiyor
- [x] `vm.max_map_count` zaten 1048576 (≥ 262144) → `90-wazuh.conf` gerekmiyor
- Kurulu: tcpdump, tmux, rsync, git, python3. Eksik: incus (apt aday 7.0.1), nmap, arpwatch, python3-venv
- Snap paketi yok (iyi; LXD/snap kurulmayacak)

### Seçilen değerler (§3)
| Yer tutucu | Değer |
| --- | --- |
| `<VM_IP>` | 192.168.23.136 (DHCP; değişirse `~/.ssh/config` güncellenir) |
| `<IOT_SUBNET>` | 10.20.0.0/24 |
| `<IOT_GW_IP>` | 10.20.0.1 |
| `<SENSOR_IOT_IP>` | 10.20.0.2 |
| `<IOT_DHCP_START>`–`<IOT_DHCP_END>` | 10.20.0.100–10.20.0.199 |
| `<QUAR_SUBNET>` / GW / DHCP | 10.20.1.0/24, 10.20.1.1, .100–.199 |
| `<SVC_SUBNET>` / GW / DHCP | 10.20.2.0/24, 10.20.2.1, .100–.199 |
| `<BROKER_MAC>` / `<BROKER_IP>` | 00:16:3e:20:02:10 / 10.20.2.10 |
| `<WAZUH_IP>` | Adım 4'te (incusbr0 subnet'i belli olunca) |

### Adım 1 ilerlemesi
- [x] Şifresiz sudo (`/etc/sudoers.d/rogue`, kullanıcı ekledi)
- [x] `lvextend -r` → `/` 56 GB
- [x] apt upgrade; incus 7.0.1, nmap, arpwatch, python3-venv, dsniff kuruldu
- [x] `rogue` → `incus-admin`; `incus admin init --minimal` → `incusbr0` = 10.160.244.1/24 (lab subnet'leriyle çakışmıyor), storage `default` (dir)
- [x] AppArmor sysctl (`/etc/sysctl.d/99-incus-apparmor.conf`, kullanıcı uyguladı) sonrası **Kontrol geçti:** `images:debian/13` container'ı IP aldı, `deb.debian.org`'a ping attı, silindi.

### Adım 2 — Köprüler ve router ✅
- [x] `/etc/netplan/60-rg-bridges.yaml` (600) → `br-iot` 10.20.0.2/24, `br-quar`, `br-svc`
- [x] Host `/etc/nftables.conf` = sadece `inet rg_host`; `nftables` enable. Ek: `nftables.service.d/override.conf` (ExecStop sadece `rg_host`'u siler, bkz. sorunlar)
- [x] `rg-router` (Debian 13): eth0 incusbr0 (DHCP, 10.160.244.190), eth1 10.20.0.1, eth2 10.20.1.1, eth3 10.20.2.1; `ip_forward=1`; dnsmasq 3 havuz + broker `dhcp-host`; `inet rg` tablosu. Dosyalar `lab/router/`.
- [x] **Kontrol geçti** (geçici Alpine `t-iot`, br-iot): DHCP'den 10.20.0.172 aldı; DNS router üzerinden çözüyor; onaysızken internet BLOCKED → `rg_approved`'a eklenince REACHED → `rg_block`'a eklenince BLOCKED (sayaçlar arttı). Host br-iot'tan router'a ping OK.

### Adım 3 — Broker ve cihazlar ✅
- [x] `mqtt-broker` (Debian 13, br-svc, 00:16:3e:20:02:10) → 10.20.2.10, mosquitto `listener 1883 0.0.0.0`, anonim
- [x] `lab/devices.yaml` (6 profil = doğru cevap etiketi), `lab/agent/device_agent.py`, `lab/agent/setup.sh`, `lab/build_lab.py`
- [x] 6 cihaz kuruldu, hepsinde `clean` snapshot

| Cihaz | İmaj | DHCP istemcisi | MAC (OUI) | Hostname | IP (ilk lease) |
| --- | --- | --- | --- | --- | --- |
| cam-01 | alpine/3.22 | udhcpc | 00:40:8c (Axis) | axis-m3045-51b2 | 10.20.0.111 |
| cam-02 | alpine/3.22 | udhcpc | 00:40:8c (Axis) | axis-m3045-77e4 | 10.20.0.123 |
| printer-01 | debian/12 | dhclient | 00:1b:a9 (Brother) | BRN001BA96C208F | 10.20.0.137 |
| plug-01 | debian/13 | dhcpcd | 00:11:50 (Belkin) | wemo-mini-5f2a | 10.20.0.138 |
| temp-01 | alpine/3.21 | udhcpc (`-O ntpsrv -O timezone`) | 00:4b:12 (Espressif) | esp32-sht31-7c1e | 10.20.0.148 |
| thermo-01 | ubuntu/24.04 | systemd-networkd | 44:61:32 (ecobee) | ecobee3-lite-21f0 | 10.20.0.169 |

- [x] **Kontrol geçti:** dnsmasq lease'lerinde 6 cihaz farklı hostname/OUI ile; dnsmasq log'unda vendor class'lar ve option 55 listeleri farklı. IP'ler geçici olarak `rg_approved`'a eklenince 6 istemci de broker'a bağlandı, 100 sn'de cam-01 ×4, cam-02 ×2, plug-01 ×10, temp-01 ×7, thermo-01 ×2 yayın (printer 300 sn aralıklı, bağlantısı görüldü). HTTP/RTSP banner'ları host'tan doğrulandı. mDNS: 8 servis örneği (cam ×2 http+rtsp, printer ipp+printer, plug http, thermo hap) cam-01 içinden zeroconf ile görüldü. Test sonrası `rg_approved` boşaltıldı.
- Not: Alpine imajı varsayılan olarak dhcpcd kullanıyor; setup.sh onu kaldırıp udhcpc'yi `/etc/local.d` ile başlatıyor. Container'ın kendi `hostname` komutu Incus adını (ör. `cam-01`) gösteriyor; ağa çıkan hostname DHCP option 12 ve mDNS'tekidir.

### Adım 5 — Proje iskeleti ✅
- [x] `arpwatch@br-iot` enable + active (kıyaslama aracı)
- [x] VM'de `~/rogueguard/.venv` (Python **3.14**): scapy 2.8.0, zeroconf 0.154, paho-mqtt 2.2, pytest 9.2, streamlit 1.67, pandas 3.1, openai 3.51, pyyaml, requests
- [x] Paket iskeleti (§8), `rogueguard/config.py`, `rogueguard/db.py` (WAL; devices, observations, events, alerts, approvals). DB: `data/rogueguard.db` (gitignore'da)

### 6.1 Keşif ✅
- `discovery/arp_scan.py` (30 sn'de bir `srp` ARP taraması + 120 sn'de bir br-iot'a mDNS PTR sorgusu, `ArpDedup`), `discovery/sniffer.py` (tek `AsyncSniffer`: ARP, DHCP option 12/55/60/61/50 + ACK'te IP→MAC, mDNS cevapları, trafik), `fingerprint/{dhcp,mdns,traffic}.py`, `discovery/events.py` (new_device / changed_device), `discovery/recorder.py` (tek yazıcı thread), `discovery/runner.py`, `python -m rogueguard discover --duration N`
- 8 birim testi geçiyor (`tests/test_discovery_units.py`)
- [x] **Bitti kontrolü:** 150 sn keşif + cihaz restart'ı → 6 cihazın hepsi `observations`'ta `arp, dhcp, traffic`; mDNS profilinde olan 5 cihaz `mdns` ile de (temp-01'in profilinde mDNS yok). mDNS'ten servis türleri ve hostname'ler doğru çıktı.
- Düzeltilen yanlış pozitifler: (1) thermo-01'in kapanışta gönderdiği DHCP RELEASE eksik option taşıdığı için "parmak izi değişti" sanıldı → parmak izi sadece DISCOVER/REQUEST'ten; (2) router'ın yönlendirdiği paketlerde kaynak IP başka cihazın olduğu için router "IP değişti" göründü → IP sadece ARP/DHCP'den izleniyor. Tekrar koşuda restart sonrası 0 yanlış olay.

### 6.2 Öğrenme modu ✅
- `sudo .venv/bin/python -m rogueguard learn --duration 150`: keşfi çalıştırır, görülen her cihazı bir kez `nmap -sT -sV` ile tarar (sadece lab alt ağına izin verir), `devices` tablosuna `approved` yazar, `inventory.yaml` üretir ve `rg_approved` setini router'da doldurur. `sync` komutu aynı seti DB'den yeniden kurar.
- Router (10.20.0.1) `infrastructure` olarak envantere girer, `rg_approved`'a eklenmez.
- Kontrol: envanterde 6 meşru cihaz + router; `rg_approved` içinde 6 IP; 14 test geçiyor.
- Benzerlik (`fingerprint/compare.py`, ağırlıklar `config.yaml`): meşru cihaz çiftlerinde skor 0.14–0.25, cam-01/cam-02 = 0.86 (bilinçli ikiz, tek istisna). Eşik `similarity_max: 0.6`. Test hem `lab/devices.yaml`'dan hem canlı envanterden çalışır.
- Bulgu: nmap, Debian cihazlarda 5355/tcp (LLMNR) açık gösterdi; port kümesi gerçek servisleri yansıtıyor.
- **Çözüldü (yayın aralığı):** br-iot köprüsü cihaz→router unicast trafiğini host'a iletmiyordu, yayın aralığı boş kalıyordu. `discovery/router_tap.py` rg-router eth1'de `tcpdump` (BPF: MQTT PUBLISH) çalıştırıp yayınları trafik penceresine besliyor; son yayın zamanı pencereler arası tutulduğu için 300 sn'lik yazıcı da ölçülüyor. 660 sn'lik learn sonrası aralıklar: plug 10, temp 15, thermo 58, cam-01/02 ~40 (düzensiz), printer 326 sn. Meşru çiftler 0.07–0.18, cam ikizi 0.86; 15 test geçiyor.

### 6.3 Karar motoru — "Bitti" koşulu geçti ✅ (16 Kasım)
- `decision/attack_map.py` (§5 tablosu), `decision/engine.py`, `python -m rogueguard protect`, `config.yaml` `decision:` bölümü (`detection_profile`, `match_min: 0.9`, `alert_cooldown: 300`).
- Motor olaylara değil **gözlemlere** bağlı (`Recorder(on_observation=...)`): `EventTracker` durumu bellekte tuttuğu için daemon yeniden başlayınca klonlanmış MAC'in ilk DHCP paketi `changed_device` üretmezdi.
- Kurallar: envanterde olmayan MAC → `unknown_device` + `pending`; approved MAC'in DHCP parmak izi (hostname, option 55, vendor class) `compare.similarity` ile `match_min` altında → `impersonation`; DHCP ACK'te IP değişimi → alarm yok, `devices.ip` güncellenir ve `on_ip_change` kancası `rg_approved`'da eski IP'yi yenisiyle değiştirir (yakın zamanda impersonation alarmı olan MAC için taşınmaz). `protect` başlarken router setlerini DB'den eşitler ve `sweep()` ile önceden görülmüş bilinmeyen MAC'leri işaretler. Pending cihazın IP'si sonradan ARP/DHCP'den doldurulur.
- 27 test geçiyor (12'si `tests/test_decision.py`).
- **Kontrol B1 (canlı):** `protect` çalışırken 6 meşru cihaz yeniden başlatıldı; hepsi DHCP DISCOVER/REQUEST gönderdi, **0 alarm** (restart sonrası bekleme süresine gerek kalmadı: RENEW/REQUEST paketleri tüm option'ları taşıyor).
- **Kontrol R1 (canlı):** `images:fedora/43` rogue container'ı br-iot'a bağlandı → `unknown_device` (T1200, pending), broker'a erişemiyor (TCP 1883 kapalı). 6 koşu (her biri yeni MAC): 6/6 yakalandı, tespit süresi 0.44–0.71 sn (medyan 0.48). arpwatch aynı cihazı `new station` olarak 6.3–9.2 sn'de gördü (medyan 8.8). Ayrıntı: `notes/R1 İlk Ölçümler.md`.
- **Henüz yapılmadı (deneylerden önce):** `full` profilinin `abnormal_behavior` (K ardışık pencere) kısmı ve `arp_guard.py` (R4 için); `full` şimdilik `fingerprint` ile aynı. IP taşıma kancası birim testli, canlı olarak B2 senaryosunda (kiralama silme) denenecek.

### Karşılaşılan sorunlar
- **systemd'li container'lar açılışta takılıyor (Ubuntu 26.10 host).** Debian 13 container'ında journald/networkd/resolved `(sd-mkuser...)` adımında asılı kalıyor, `eth0` IP almıyor; host dmesg'de `incus-<ad>` profili için AppArmor ptrace DENIED satırları. Neden: Ubuntu'ya özgü AppArmor kısıtı `kernel.apparmor_restrict_unprivileged_unconfined=1` (ve `..._userns=1`). Incus geliştiricisinin önerdiği çözüm bu sysctl'i 0 yapmak (lxc/incus#3251; Zabbly paketleri bunu artık otomatik yapıyor, Ubuntu'nun incus paketi yapmıyor). Host güvenlik ayarı olduğu için kullanıcı kendisi uyguladı; sonrasında sorun çözüldü.
- Mac'teki proje klasörünün git kökü yanlışlıkla ev dizini (`/Users/gultekinqwe`) çıktı → proje klasöründe ayrı `git init` yapıldı.
- İlk `ssh rogue` denemesi "No route to host" verdi; VM açıktı, birkaç saniye sonra düzeldi (Fusion NAT köprüsü geç ayağa kalktı).
- **`systemctl restart nftables` Incus'un `inet incus` tablosunu sildi.** Ubuntu'nun `nftables.service` unit'inde `ExecStop=/usr/sbin/nft flush ruleset` var; dosyada `flush ruleset` olmasa bile restart/stop her şeyi siler. `systemctl restart incus` ile Incus kuralları geri geldi; kalıcı çözüm `lab/host/nftables-override.conf` → `/etc/systemd/system/nftables.service.d/override.conf` (ExecStop sadece `delete table inet rg_host`). Doğrulandı: restart sonrası iki tablo da duruyor.
- **rg-router'da dnsmasq upstream'i.** Container'ın `/etc/resolv.conf`'u systemd-resolved stub'ı (127.0.0.53). `resolv-file=/run/systemd/resolve/resolv.conf` eklendi → upstream incusbr0 DNS'i (10.160.244.1).
- **pip kurulumu 8+ dk sessizce takıldı** (`-q` ile tüm paketler tek seferde, Python 3.14). Çekirdek paketler ve streamlit/pandas/openai ayrı ayrı kurulunca birkaç dakikada bitti.

- **VM askıya alınıp devam ettirilince `incusbr0` IPv4 adresini kaybetti** (link down → sadece IPv6LL kaldı); rg-router'ın incusbr0 ayağı da IPv4'süz kaldı, onaylı cihazların interneti kesildi. Çözüm: `sudo systemctl restart incus` (container'lar durmaz) + `incus exec rg-router -- networkctl reconfigure eth0`. br-iot/br-svc etkilenmedi.
- **Yeniden başlayan Alpine cihazlar yeni IP aldı, `rg_approved` eski IP'de kaldı** → cihaz broker'a ulaşamadı. Çözüm: karar motorunun `on_ip_change` kancası + `protect` açılışında `sync`.
- `sudo pkill -f "<desen>"` kendi ssh komut satırıyla da eşleşip oturumu öldürdü (iki kez). Daemon'u `tmux kill-session` ile kapat.

### Sıradaki adım
6.4 karantina (`containment/quarantine.py`: alarm aksiyonunu uygula, `contained_at`), ardından `decision/arp_guard.py` ve `abnormal_behavior`. Ara değerlendirme (19 Kasım) teslimlerinin hepsi hazır.
