# RogueGuard — Ajan Talimatları

Bu repo, Siber Güvenlik dersi dönem projesi **RogueGuard: Rogue IoT Device Detection and Containment** içindir. Araç, izole bir lab ağındaki IoT cihazlarını keşfeder, parmak izi çıkarır, öğrenilmiş envanterle karşılaştırır ve sahte ya da taklitçi cihazları otomatik olarak karantinaya alır.

Ayrıntılı kurulum rehberi (insan için): https://claude.ai/artifact/14angkkLWbvXJFEgnYPxYM
Bu dosya o rehberin ajanlar için özetidir. Çelişki olursa **bu dosya geçerlidir**.

---

## 0. Nerede ve nasıl çalışırsın

Sen Mac'teki bu repoda çalışıyorsun. **Lab'ın tamamı (Incus, köprüler, container'lar, RogueGuard daemon) Ubuntu Server VM'inin içinde çalışır.** VM'e Mac'ten şifresiz bağlanırsın:

```bash
ssh rogue                         # etkileşimli oturum
ssh rogue '<komut>'               # tek komut
ssh rogue 'sudo <komut>'          # root gereken komut (şifresiz sudo varsa)
ssh -t rogue 'tmux new -As rg'    # uzun işler (deneyler, learn modu) için kalıcı oturum
```

- `rogue` Mac'teki `~/.ssh/config` içindeki bir takma ad: kullanıcı `rogue`, anahtar `~/.ssh/rogueguard`. IP'yi elle yazma, hep `ssh rogue` kullan.
- **İlk iş bağlantıyı doğrula:** `ssh rogue 'hostname && whoami && sudo -n true && echo SUDO_OK'`. `rogueguard-lab`, `rogue` ve `SUDO_OK` görmelisin. Bağlanamıyorsan ya da `SUDO_OK` gelmiyorsa dur ve kullanıcıya sor; VM kapalı olabilir veya IP'si değişmiş olabilir.
- Dosya kopyalama: `rsync -a --exclude .venv --exclude .git ./ rogue:~/rogueguard/` ya da `scp <dosya> rogue:<yol>`.
- Container içinde komut: `ssh rogue 'incus exec <container> -- <komut>'`.
- Mac'te sadece kod yazılır ve git işlemleri yapılır. Mac'e Incus, scapy daemon'u ya da lab bileşeni kurma.

---

## 1. Kesin kurallar

1. **Sadece lab içinde çalış.** Tarama, dinleme, ARP spoofing ve engelleme yalnızca VM içindeki `br-iot`, `br-quar`, `br-svc` köprülerinde yapılır. Mac'in ağına, Fusion NAT ağına (`enp2s0`) veya internete asla tarama/saldırı trafiği gönderme.
2. **Her adımın "Kontrol" maddesi geçmeden sonrakine geçme.** Geçmezse hatayı düzelt ya da durup kullanıcıya hata çıktısıyla birlikte sor.
3. **VM host'una Docker, LXD veya snap paketleri kurma.** Docker sadece `wazuh` Incus container'ının içinde çalışır.
4. **Host'ta `nft flush ruleset` çalıştırma.** Incus'un kendi kurallarını siler. Host'ta sadece `inet rg_host` tablosuna dokun.
5. **Gizli bilgileri commit'leme.** Groq API anahtarı vb. sadece `.env` içinde durur; `.env` `.gitignore`'da olmalı. Sohbete veya log'a yazma.
6. **Geri alınamaz işlemlerden önce sor:** VM'i silmek, snapshot geri yüklemek, disk/LVM değişikliği (Adım 1'deki `lvextend` hariç), kullanıcı hesabı değişikliği.
7. **Kod okunabilir olmalı.** Kullanıcı kodu hocaya savunacak. Her modülün başına 2–3 satırlık amaç yorumu yaz; karmaşık kararları commit mesajında açıkla. Gereksiz soyutlama yapma.
8. Her anlamlı adımdan sonra küçük bir commit at ve `PROGRESS.md`'yi güncelle (bkz. §9).

---

## 2. Ortam

| Ne | Değer |
| --- | --- |
| Fiziksel makine | MacBook Pro, Apple Silicon (arm64), 16 GB RAM |
| Hipervizör | VMware Fusion, ağ: NAT ("Share with my Mac") |
| VM | Ubuntu Server **26.10** arm64, hostname `rogueguard-lab` |
| VM kaynakları | 4 çekirdek, 10 GB RAM, 60 GB disk (LVM) |
| VM kullanıcısı | `rogue` |
| VM'e erişim | Mac'ten `ssh rogue` (anahtar: `~/.ssh/rogueguard`, alias `~/.ssh/config` içinde) |
| VM ağ arayüzü | `enp2s0` (DHCP, Fusion NAT) |

- Mac'teki bir ajan VM'de komutu `ssh rogue '<komut>'` ile çalıştırır. Uzun işler için `ssh rogue` içinde `tmux` kullan.
- Kod Mac'teki bu repoda yazılır; VM'e `rsync -a --exclude .venv --exclude .git ./ rogue:~/rogueguard/` ile senkronlanır (ya da GitHub üzerinden `git pull`).
- Apple Silicon kısıtı: OPNsense ve x86 OVA'lar çalışmaz. Bu yüzden firewall **nftables + dnsmasq çalıştıran `rg-router` container'ıdır**, Wazuh **Docker ile container içindedir**.
- Ubuntu 26.10 kullanılıyor (rehberde 24.04 yazar). Bir paket adı bulunamazsa `apt search` ile karşılığını bul, `PROGRESS.md`'ye not düş.

---

## 3. Değerler

Aşağıdaki değerleri ilk kez gerektiğinde seç, `config.yaml`'a ve bu tabloya yaz, sonra hep aynısını kullan. Seçtiğin subnet'ler Fusion NAT subnet'i (`enp2s0`) ve `incusbr0` ile çakışmamalı.

| Yer tutucu | Değer |
| --- | --- |
| `<VM_IP>` | 192.168.23.136 (`ssh rogue 'ip -br a show enp2s0'`; Fusion NAT 192.168.23.0/24) |
| `<IOT_SUBNET>` / `<IOT_PREFIX>` | 10.20.0.0 / 24 |
| `<IOT_GW_IP>` (rg-router eth1) | 10.20.0.1 |
| `<SENSOR_IOT_IP>` (host'un `br-iot` adresi, DHCP havuzu dışında) | 10.20.0.2 |
| `<IOT_DHCP_START>`–`<IOT_DHCP_END>` | 10.20.0.100–10.20.0.199 |
| `<QUAR_SUBNET>`, `<QUAR_GW_IP>`, DHCP aralığı | 10.20.1.0/24, 10.20.1.1, .100–.199 |
| `<SVC_SUBNET>`, `<SVC_GW_IP>`, DHCP aralığı | 10.20.2.0/24, 10.20.2.1, .100–.199 |
| `<BROKER_MAC>` / `<BROKER_IP>` | 00:16:3e:20:02:10 / 10.20.2.10 |
| `<WAZUH_IP>` (`incusbr0` içinde) | |

---

## 4. Mimari

Tek VM içinde her şey:

| Bileşen | Nerede | Köprü |
| --- | --- | --- |
| RogueGuard daemon, Streamlit, arpwatch | VM host'u (doğrudan) | `br-iot` (statik IP, dinleme/tarama), `incusbr0` |
| `rg-router` (nftables + dnsmasq) | Incus container, Debian 13 | eth0 `incusbr0`, eth1 `br-iot`, eth2 `br-quar`, eth3 `br-svc` |
| `mqtt-broker` (Mosquitto) | Incus container, Debian 13 | `br-svc` |
| 6 meşru cihaz + rogue cihazlar | Incus container | `br-iot` |
| `wazuh` (single-node Docker) | Incus container, `security.nesting=true`, `limits.memory=5GiB` | `incusbr0` |

- Broker ayrı köprüde: cihaz→broker trafiği `rg-router`'dan geçer ve engellenebilir.
- Aynı köprü içindeki L2 saldırıları (ARP spoofing) router'dan geçmez; bunlara karşı cihaz `br-quar`'a taşınır.
- Host, IoT köprüleri arasında yönlendirme yapmaz (`inet rg_host` tablosu `br-*` forward trafiğini düşürür). Tek yol `rg-router`.

**Bellek modları:** Geliştirme ve deneyler sırasında `wazuh` kapalı (`incus stop wazuh`). Sadece SIEM testi ve demo için aç.

### rg-router firewall mantığı

`table inet rg` içinde iki set: `rg_approved`, `rg_block` (ipv4_addr).

| Cihaz durumu | Erişim |
| --- | --- |
| Onaysız (pending) | Sadece DHCP ve DNS |
| `rg_approved` | Broker TCP 1883 + internet |
| `rg_block` | Hiçbir şey (kural `established`'dan önce, açık bağlantılar da kesilir) |
| `br-quar`'da | Sadece DHCP |

Setler router yeniden başlayınca boşalır → RogueGuard açılışta veritabanından yeniden doldurur (`router.sync()`).

---

## 5. Hocanın geri bildirimi (zorunlu)

1. **Cihazlar birbirinden farklı olmalı.** Aynı imajdan üretilen cihazların parmak izleri neredeyse aynı olur. Her cihaz farklı imaj, DHCP istemcisi, OUI, hostname, vendor class, port ve mDNS servisi kullanır (§6). Bunu bir pytest benzerlik testiyle kanıtla.
2. **ATT&CK Enterprise matrisi kullan, ICS değil.**
3. **LLM ile cihaz türü tahmini ekle** (Groq ücretsiz katman) ve kural tabanlı sınıflandırıcıyla doğruluğunu karşılaştır.

### ATT&CK eşlemesi

| Tespit türü | Teknik | Önem | Aksiyon |
| --- | --- | --- | --- |
| `unknown_device` | T1200 Hardware Additions | orta | pending, engelleme yok, dashboard onayı |
| `impersonation` | T1036 Masquerading | yüksek | karantina (`br-quar`) |
| `arp_spoofing` | T1557.002 ARP Cache Poisoning | yüksek | karantina |
| `abnormal_scan` | T1046 Network Service Discovery | yüksek | `rg_block` |
| `abnormal_behavior` | — | yüksek | `rg_block` |

---

## 6. Cihaz profilleri

Tüm profiller `lab/devices.yaml` içinde durur; bu dosya aynı zamanda doğru cevap etiketidir.

| Cihaz | Tür | İmaj | DHCP istemcisi | Portlar | mDNS | MQTT |
| --- | --- | --- | --- | --- | --- | --- |
| cam-01 | camera | `images:alpine/<SURUM>` | udhcpc | 80, 554 | `_http._tcp`, `_rtsp._tcp` | hareket olayı, düzensiz |
| printer-01 | printer | `images:debian/12` | dhclient | 631, 9100 | `_ipp._tcp`, `_printer._tcp` | durum, 300 s |
| plug-01 | smart_plug | `images:debian/13` | dhcpcd | 80, `<PRIZ_PORTU>` | `_http._tcp` | güç, 10 s |
| temp-01 | sensor | `images:alpine/<SURUM>` | udhcpc (farklı vendor class) | yok | yok | sıcaklık, 15 s |
| thermo-01 | thermostat | `images:ubuntu/24.04` (yoksa güncel) | systemd-networkd | 80 | `_hap._tcp` | ayar noktası, 60 s |
| cam-02 | camera | cam-01 ile aynı | udhcpc | 80, 554 | aynı | aynı |

- cam-02 bilerek cam-01'in ikizi (sadece MAC son 3 byte ve hostname farklı). Benzerlik testinde beklenen tek istisna; raporda sınırlılık olarak kullanılacak.
- OUI'leri `/usr/share/nmap/nmap-mac-prefixes`'ten gerçek üreticilerden seç.
- Tek bir `lab/agent/device_agent.py` profile göre: portlarda dinler ve banner döner (HTTP `Server`, RTSP), `python-zeroconf` ile mDNS kaydeder, `paho-mqtt` ile `<BROKER_IP>:1883`'e yayın yapar (aralığa küçük jitter).
- Container kurulum sırası: önce `incusbr0`'da başlat (internet için), paketleri/ajanı kur, durdur, `eth0`'ı `nictype=bridged parent=br-iot hwaddr=<OUI>:xx:xx:xx` yap, başlat, `incus snapshot create <ad> clean`.

---

## 7. Yapılacaklar (sırayla)

Durum işaretleri: `[x]` bitti, `[ ]` yapılacak, `[?]` kullanıcı yapmış olabilir, kontrol et.

### Adım 1 — VM temel ayarları
- [x] Ubuntu 26.10 arm64 kuruldu, hostname `rogueguard-lab`, kullanıcı `rogue`
- [x] Mac'ten `ssh rogue` (anahtarla) çalışıyor
- [x] Kök bölüm büyütüldü: `df -h /` ~57 GB göstermeli. Değilse: `sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv`
- [x] Şifresiz sudo: `sudo -n true` başarılı olmalı. Değilse kullanıcıdan iste (`/etc/sudoers.d/rogue`)
- [x] `apt update && apt -y upgrade`; `apt install -y incus git nmap tcpdump python3-venv tmux rsync arpwatch`
- [x] 4 GB swap (`/swapfile`, fstab'a ekle)
- [x] `vm.max_map_count=262144` (`/etc/sysctl.d/90-wazuh.conf`)
- [x] `usermod -aG incus-admin rogue`, `incus admin init --minimal`
- **Kontrol:** geçici bir `images:debian/13` container'ı internete ping atabiliyor; sonra silinir.

### Adım 2 — Köprüler ve router
- [x] `/etc/netplan/60-rg-bridges.yaml`: `br-iot` (`<SENSOR_IOT_IP>/<IOT_PREFIX>`), `br-quar`, `br-svc`; hepsi `link-local: []`, `stp: false`, `forward-delay: 0`; dosya izni 600; `netplan apply`
- [x] Host `/etc/nftables.conf`: sadece `inet rg_host` tablosu, forward hook priority -5, `br-iot|br-quar|br-svc` giriş/çıkışını drop. `flush ruleset` yok. `systemctl enable --now nftables`
- [x] `rg-router` container: 4 NIC, `nftables` + `dnsmasq`, systemd-networkd ile statik adresler, `ip_forward=1`, dnsmasq 3 DHCP aralığı + broker için `dhcp-host`, `inet rg` tablosu (§4)
- **Kontrol:** `br-iot`'a bağlanan geçici container router'dan IP alıyor; `rg_approved`'a eklenene kadar internete çıkamıyor, eklenince çıkabiliyor.

### Adım 3 — Broker ve cihazlar
- [x] `mqtt-broker` (`listener 1883 0.0.0.0`, `allow_anonymous true`), `br-svc`, `hwaddr=<BROKER_MAC>`
- [x] `lab/devices.yaml`, `lab/agent/` (device_agent.py, setup.sh), `lab/build_lab.py`
- [x] 6 cihazı oluştur, `clean` snapshot al
- **Kontrol:** `incus exec rg-router -- cat /var/lib/misc/dnsmasq.leases` → 6 cihaz, farklı hostname ve üretici. IP'leri geçici olarak `rg_approved`'a ekleyince `incus exec mqtt-broker -- mosquitto_sub -t '#' -v` tüm yayınları gösteriyor.

### Adım 4 — Wazuh (ara değerlendirmeden sonra yapılabilir)
- [ ] `wazuh` container (`images:ubuntu/24.04`, `security.nesting=true`, `limits.memory=5GiB`), statik `<WAZUH_IP>`, proxy device `tcp:0.0.0.0:8443 → 127.0.0.1:443`
- [ ] İçinde `docker.io`, compose, `wazuh-docker` single-node (güncel etiket), indexer `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`
- [ ] Manager conf: `<remote>` syslog, udp 514, `allowed-ips` = `incusbr0` subnet'i; 514/udp compose'da yayınlı
- [ ] `local_decoder.xml` (program_name `^rogueguard`, JSON_Decoder), `local_rules.xml` (100200 taban kural; 100201–100205 her `type` için, `<mitre><id>` §5'teki gibi)
- İzin hatası olursa son çare: `security.privileged=true` (sadece lab).
- **Kontrol:** `logger -n <WAZUH_IP> -P 514 -d -t rogueguard '{"type":"arp_spoofing",...}'` → dashboard'da doğru kural ve T1557.002.

### Adım 5 — Proje iskeleti
- [x] `systemctl enable --now arpwatch@br-iot`
- [x] VM'de `~/rogueguard`, venv; `pip install scapy pyyaml requests streamlit pandas zeroconf openai paho-mqtt pytest`
- [x] Klasör yapısı (§8), `config.yaml`, SQLite şeması (WAL)
- Daemon root/`CAP_NET_RAW,CAP_NET_ADMIN` ile çalışır (systemd unit'te `AmbientCapabilities`).

### Adım 6 — Modüller (her biri "Bitti" koşuluyla)
- **6.1 Keşif:** periyodik `srp` ARP taraması (`iface=br-iot`); tek `sniff` ile ARP, DHCP (option 12/55/60/61), mDNS (5353); trafik örneği (MAC başına hedef ip:port, yayın aralığı). Olaylar: `new_device`, `changed_device`. *Bitti:* 6 cihaz `observations` tablosunda ARP+DHCP+mDNS ile.
- **6.2 Öğrenme modu:** `python -m rogueguard learn --duration <SN>`; cihaz başına bir kez `nmap -sT -sV -oX -`; sonunda `devices` (approved), `inventory.yaml`, `rg_approved` doldurulur. pytest: meşru cihazların ikili parmak izi benzerliği `< ESIK` (cam-01/cam-02 açıkça istisna). *Bitti:* envanterde 6 cihaz, test geçiyor.
- **6.3 Karar motoru:** özellik bazında skor (OUI, hostname, option 55 sırası, vendor class birebir; port/mDNS/hedef Jaccard; yayın aralığı toleransla). Ağırlık/eşikler `config.yaml`'da. `detection_profile`: `allowlist` | `fingerprint` | `full`. Yanlış pozitif önlemleri: DHCP ACK'te IP→MAC güncelle, restart sonrası bekleme süresi, `abnormal_behavior` için K ardışık pencere. *Bitti:* bilinmeyen container → `unknown_device` alarmı ve `pending`. **← 19 Kasım hedefi**
- **6.4 Karantina:** `containment/router.py` (`incus exec rg-router -- nft add/delete element inet rg <set> { ip }`, `sync()`), `containment/quarantine.py` (`incus list --format json` → `expanded_devices.eth0.hwaddr` ile MAC eşle → `incus config device set <ad> eth0 parent=br-quar`). Aynı MAC'li iki container varsa envanterle uyuşmayanı seç. `alerts.detected_at` / `contained_at` yaz.
- **6.5 Alarm iletimi:** `SysLogHandler(("<WAZUH_IP>", 514))`, format `'%(asctime)s rogueguard-lab rogueguard: %(message)s'`, datefmt `'%b %d %H:%M:%S'`, mesaj JSON (`type, mac, ip, severity, attack_id, action, reason`). Wazuh kapalıyken hata vermemeli.
- **6.6 Dashboard (Streamlit):** Cihazlar, Onay bekleyenler (Onayla/Reddet → `approvals` tablosuna yazar; daemon okur), Alarmlar, Deney sonuçları. `@st.fragment(run_every="5s")`. Mac'ten `http://<VM_IP>:8501`.
- **6.7 Cihaz türü:** `classify/rules.py` (etiketler: camera, printer, smart_plug, sensor, thermostat, unknown); `classify/llm.py` (Groq, OpenAI uyumlu `https://api.groq.com/openai/v1`, `temperature=0`, JSON çıktı `{label, confidence, reason}`, parmak izi hash'iyle önbellek, 429'da `retry-after`). Model adını ve limitleri Groq konsolundan doğrula. **LLM çıktısı sadece dashboard'da "tahmini tür"; karar motoruna asla girmez.**

### Adım 7 — Deneyler
- Rogue imajı meşru cihazlarda kullanılmayan bir imaj (ör. `images:fedora/<SURUM>`).
  - R1 hiçbir şey gizlemez · R2 kurbanın MAC'ini kopyalar (kurban kapalı; ayrıca kurban açıkken ayrı senaryo) · R3 MAC+hostname+port+mDNS · R4 R3 + `arpspoof -t <KURBAN_IP> <IOT_GW_IP>` (`ip_forward=1`) · R3+ (ops.) DHCP option'larını da kopyalar.
- Normal olaylar: B1 restart, B2 IP değişimi (dnsmasq kiralamasını sil + restart), B3 yeni meşru cihaz + onay, B4 sessiz süre.
- `experiments/run_scenarios.py`: 3 konfigürasyon × 8 senaryo × 10 tekrar. Her koşu: sıfırla (rogue'ları sil, `clean` snapshot, `rg_block` boşalt, envanter DB kopyası, daemon'u profille yeniden başlat) → dengelenme → `t0` → senaryo → `alerts` yokla → `results.csv` (yakalandı mı, tür doğru mu, ttd, ttc, yanlış engellenen meşru cihaz). arpwatch: `journalctl -u arpwatch@br-iot --since @<t0>` içinde `new station`, `changed ethernet address`, `flip flop`. Kaldığı yerden devam edebilmeli; gece `tmux`'ta çalışır, Wazuh kapalı.
- `experiments/metrics.py`: konfigürasyon × senaryo için tespit oranı, ortalama/medyan ttd ve ttc, yanlış pozitif; arpwatch ayrı sütun.
- LLM deneyi: 30–50 etiketli parmak izi JSON'u (canlı + `devices.yaml` varyantları: sadece portlar, hostname'siz, yanıltıcı hostname); kurallar / LLM / hibrit için doğruluk, confusion matrix, gecikme; prompt injection: rogue cihazın mDNS adına veya vendor class'ına talimat metni koy, etiket değişiyor mu ölç.

---

## 8. Repo yapısı

```
rogueguard/
├── CLAUDE.md  PROGRESS.md  config.yaml  .env  .gitignore
├── rogueguard/
│   ├── __main__.py            # learn | protect | sync
│   ├── db.py                  # SQLite (WAL): devices, observations, alerts, approvals
│   ├── discovery/             # arp_scan.py, sniffer.py, events.py
│   ├── fingerprint/           # vendor.py, dhcp.py, ports.py, mdns.py, traffic.py, compare.py
│   ├── decision/              # engine.py, arp_guard.py, attack_map.py
│   ├── containment/           # router.py, quarantine.py
│   ├── alerting/syslog.py
│   └── classify/              # rules.py, llm.py
├── dashboard/app.py
├── lab/                       # devices.yaml, rogues.yaml, build_lab.py, agent/, router/, wazuh/
├── experiments/               # run_scenarios.py, metrics.py, results.csv
└── tests/
```

Lab'ın kendisi de kod olarak tutulur: router ve host nftables dosyaları, netplan, dnsmasq ve Wazuh decoder/rule dosyaları `lab/` altında versiyonlanır ve oradan VM'e kopyalanır.

---

## 9. Takvim ve raporlama

| Tarih | Hedef |
| --- | --- |
| 19 Kasım 2026 | Ara değerlendirme: Adım 1–3 + 6.1–6.3, benzerlik tablosu, ATT&CK Enterprise tablosu, LLM planı, R1 için ilk ölçümler |
| Kasım sonu | Karantina, Wazuh, dashboard, rogue seviyeleri, deneyler, arpwatch kıyaslaması, LLM deneyi |
| 1–5 Aralık 2026 | Final demo ve rapor |

`PROGRESS.md` her oturum sonunda güncellenir:
- tamamlanan adımlar ve geçen "Kontrol"ler,
- seçilen değerler (§3),
- karşılaşılan sorunlar ve çözümleri (rapordaki "karşılaşılan zorluklar" bölümü için),
- sıradaki adım.
