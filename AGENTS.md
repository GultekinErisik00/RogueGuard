# AGENTS.md — RogueGuard

Bu dosya, **RogueGuard: Rogue IoT Device Detection and Containment** dönem projesi için ajan talimatlarıdır.
Proje, izole bir lab ağındaki IoT cihazlarını keşfeder, parmak izini çıkarır, öğrenilmiş envanterle karşılaştırır ve sahte/taklitçi/saldırgan cihazları otomatik olarak karantinaya alır veya engeller.

> Not: `CLAUDE.md` ve `PROGRESS.md` önceki oturumların ayrıntılı kaydını tutar; güncel ilerleme için `PROGRESS.md` ve `notes/İlerleme Raporu.md` dosyalarına bak.

---

## 1. Çalışma Ortamı ve Temel İş Akışı

- **Kod düzenleme ve git:** Mac'te bu repoda yapılır. Mac'te Incus, scapy veya `.venv` yoktur; `pytest` Mac'te çalışmaz.
- **Lab ve çalıştırma:** Tüm bileşenler (Incus, köprüler, container'lar, RogueGuard daemon, `pytest`) Ubuntu Server **26.10** arm64 VM'i (`rogueguard-lab`, VMware Fusion NAT) içinde çalışır.
- **VM erişimi:** Daima `~/.ssh/config` takma adı `ssh rogue` kullan (IP elle yazılmaz; anahtar `~/.ssh/rogueguard`).
  - İlk iş bağlantıyı doğrula: `ssh rogue 'hostname && whoami && sudo -n true && echo SUDO_OK'`
- **Mac → VM senkronizasyon:**
  ```bash
  rsync -a --exclude .venv --exclude .git --exclude .obsidian --exclude .agents --exclude data ./ rogue:~/rogueguard/
  ```
  **`data/` mutlaka hariç tutulur** — VM'deki canlı SQLite veritabanını (`data/rogueguard.db`, öğrenilmiş envanter) ezmemek için.
- **Çalışma döngüsü:** Mac'te düzenle → `rsync` → VM'de test:
  ```bash
  ssh rogue 'cd ~/rogueguard && .venv/bin/python -m pytest -q'
  ssh rogue 'cd ~/rogueguard && .venv/bin/python -m pytest -q tests/test_decision.py::test_adı'
  ```
  Çıplak `pytest` kullanma; `.venv/bin/python -m pytest` kullan.
- **Daemon komutları (VM'de `~/rogueguard`, root gerekir):**
  - `sudo .venv/bin/python -m rogueguard discover --duration 150`
  - `sudo .venv/bin/python -m rogueguard learn --duration 660` (sadece `clean` snapshot ve rogue'suz lab ile)
  - `sudo .venv/bin/python -m rogueguard protect` (uzun süreli / canlı test için `tmux` içinde)
  - `sudo .venv/bin/python -m rogueguard sync`
- VM'de `sqlite3` CLI yoktur; DB sorguları `.venv/bin/python -c "import sqlite3; ..."` ile yapılır.
- Daemon'u `tmux` içinde çalıştır ve `tmux kill-session` ile kapat; `pkill -f` kendi SSH komutunu da öldürür.

---

## 2. Kesin Kurallar

1. **Sadece lab içinde çalış.** Tarama (`nmap`), dinleme (`scapy`/`tcpdump`), ARP spoofing ve engelleme yalnızca VM içindeki `br-iot`, `br-quar`, `br-svc` köprülerinde yapılır. Mac ağına, Fusion NAT'a (`enp2s0`) veya internete asla tarama/saldırı trafiği gönderme.
2. **Kontrol geçmeden sonrakine geçme.** Her modül/adım için birim testleri + canlı doğrulama geçmeden bir sonraki adıma geçme.
3. **VM host'una Docker, LXD veya snap kurma.** Docker yalnızca `wazuh` Incus container'ının içinde çalışır.
4. **Host'ta asla `nft flush ruleset` çalıştırma.** Incus'un kendi kurallarını siler. Host'ta sadece `inet rg_host` tablosuna dokun (`/etc/systemd/system/nftables.service.d/override.conf` kurulu olmalı). Yanlışlıkla silinirse `sudo systemctl restart incus` geri getirir.
5. **Gizli bilgileri commit'leme veya loglama.** `GROQ_API_KEY` vb. yalnızca `.env` içinde durur (`.gitignore`'da).
6. **Geri alınamaz işlemlerden önce kullanıcıya sor:** VM/container silmek, snapshot geri yüklemek (otomatik deney betiği hariç), disk/LVM veya kullanıcı hesabı değişikliği.
7. **Okunabilir ve savunulabilir kod yaz.** Kullanıcı kodu hocaya savunacak:
   - Her modülün başına 2–3 satırlık Türkçe amaç docstring'i yaz.
   - Gereksiz soyutlama ve aşırı mühendislikten kaçın; mevcut sade tarza uy.
   - Karmaşık kararları commit mesajında açıkla.
8. **Küçük commit + `PROGRESS.md` güncellemesi.** Her anlamlı adımdan sonra küçük bir commit at ve `PROGRESS.md`'yi güncelle (tamamlanan adımlar, geçen kontroller, karşılaşılan sorunlar, sıradaki adım).

---

## 3. Ağ ve Lab Değerleri

Tüm adresler `config.yaml` ile tutarlı olmalıdır:

| Bileşen / Değer | Adres / Bilgi |
| --- | --- |
| VM (`rogueguard-lab`, `enp2s0`) | `192.168.23.136` (Fusion NAT `192.168.23.0/24`) |
| `incusbr0` | `10.160.244.1/24` |
| `br-iot` (IoT ağı) | `10.20.0.0/24`, GW `10.20.0.1` (`rg-router` eth1), Host sensör `10.20.0.2`, DHCP `.100–.199` |
| `br-quar` (Karantina) | `10.20.1.0/24`, GW `10.20.1.1` (`rg-router` eth2), DHCP `.100–.199` |
| `br-svc` (Servisler) | `10.20.2.0/24`, GW `10.20.2.1` (`rg-router` eth3), DHCP `.100–.199` |
| `mqtt-broker` (Mosquitto) | `10.20.2.10:1883`, MAC `00:16:3e:20:02:10` (`br-svc`) |
| `wazuh` (`incusbr0`) | Adım 4'te belirlenecek (`config.yaml` `network.wazuh_ip`) |

**6 Meşru Cihaz (`lab/devices.yaml` = doğru cevap etiketi):**
`cam-01` (Axis, alpine/3.22, udhcpc), `cam-02` (Axis, cam-01'in bilinçli ikizi — tek benzerlik istisnası), `printer-01` (Brother, debian/12, dhclient), `plug-01` (Belkin, debian/13, dhcpcd), `temp-01` (Espressif, alpine/3.21, udhcpc + extra opt55), `thermo-01` (ecobee, ubuntu/24.04, systemd-networkd).

**Bellek modu:** Geliştirme ve deneylerde `wazuh` kapalı (`incus stop wazuh`); yalnızca SIEM testi ve demo için açılır.

---

## 4. Mimari ve Veri Akışı

```text
sniffer (br-iot) + arp_scan + router_tap (rg-router eth1)
    ──► Recorder (tek yazıcı thread) ──► observations (SQLite WAL)
            ├─► EventTracker ──► events (new_device / changed_device)
            └─► on_observation ──► DecisionEngine ──► alerts, devices(pending)
port_tap (br-iot veth portları) ──► DecisionEngine.on_arp / on_syn (sadece profile=full)
DecisionEngine ──► on_alert ──► Containment (br-quar / rg_block / arp_heal)
```

Kritik tasarım ilkeleri (kodu değiştirirken bozma):
- **SQLite tek iletişim kanalıdır (`data/rogueguard.db`, WAL).** Daemon yazar; Streamlit dashboard yalnızca `approvals` tablosuna (`approve`/`reject`) yazar, daemon okuyup uygular. Bağlantı thread'ler arası paylaşılmaz (`Recorder` kendi thread'inde, `DecisionEngine` `threading.local()` ile bağlanır).
- **Karar motoru olaylara değil gözlemlere bağlıdır** (`Recorder(on_observation=...)`). `EventTracker` bellek-içi olduğu için daemon restart sonrası klonlanmış MAC'i kaçırmamak için gözlemler doğrudan işlenir.
- **Üç dinleme noktası (köprü unicast'i host'a iletmez):**
  1. `sniffer.py`: `br-iot` üzerinde broadcast/multicast (ARP, DHCP, mDNS) ve host'a gelen trafik.
  2. `router_tap.py`: `rg-router` `eth1`'de `tcpdump` ile MQTT PUBLISH yakalama (yayın aralığı).
  3. `port_tap.py`: `br-iot` `brif` veth arayüzlerinde (SPAN karşılığı) cihazlar arası ARP ve TCP SYN.
- **Tek profil ve tek skor fonksiyonu:** `fingerprint/profile.py` (canlı gözlem ve `devices.yaml`) ve `engine.inventory_profile` aynı sözlüğü üretir; `fingerprint/compare.py` tek skor fonksiyonudur.
- **Parmak izi kaynak kısıtları:** DHCP parmak izi yalnızca `discover`/`request` paketlerinden okunur (`release`/`ack` hariç). IP yalnızca `arp`/`dhcp`'den güncellenir (yönlendirilen trafikte kaynak IP başka cihazın olabilir).
- **Alarm ≠ aksiyon:** Karar motoru `alerts` yazar; uygulama `containment/actions.py` içindedir (`on_alert`). `rg-router` nftables setleri (`rg_approved`, `rg_block`) router restart'ında boşalır; `protect` açılışta `sync` yapar.
- **LLM sınır kuralı:** LLM cihaz türü tahmini **yalnızca dashboard'da bilgi amaçlı** gösterilir; **karar motoruna asla girmez** (hostname/mDNS/vendor_class saldırgan kontrolündedir).

---

## 5. Hocanın Zorunlu Geri Bildirimleri ve ATT&CK Eşlemesi

1. **Cihazlar birbirinden farklı olmalı** — `tests/test_learn_and_similarity.py` ile kanıtlı (`similarity_max: 0.6`, meşru çiftler 0.07–0.18, ikiz kameralar 0.86).
2. **MITRE ATT&CK Enterprise matrisi kullanılır (ICS değil):**

| Tespit türü | Teknik | Önem | Aksiyon |
| --- | --- | --- | --- |
| `unknown_device` | `T1200` Hardware Additions | `medium` | `pending` (engelleme yok, dashboard onayı) |
| `impersonation` | `T1036` Masquerading | `high` | `quarantine` (`br-quar`) |
| `arp_spoofing` | `T1557.002` ARP Cache Poisoning | `high` | `quarantine` (`br-quar`) + `arp_heal` |
| `abnormal_scan` | `T1046` Network Service Discovery | `high` | `block` (`rg_block`) |
| `abnormal_behavior` | — | `high` | `block` (`rg_block`) |

3. **LLM (Groq ücretsiz katman) + kural tabanlı cihaz türü tahmini** ve doğruluk + prompt injection kıyası.

---

## 6. Proje Durumu ve Kalan İşler

### Tamamlananlar (54 pytest testi geçiyor)
- [x] **Adım 1–3:** VM, `br-iot`/`br-quar`/`br-svc`, `rg-router`, `mqtt-broker`, 6 meşru cihaz (`clean` snapshot).
- [x] **Adım 5 & 6.1–6.6 + `full` profil:** SQLite şeması, keşif (`sniffer`, `arp_scan`, `router_tap`, `port_tap`, `recorder`), `learn` + `nmap` + benzerlik testi, karar motoru (`allowlist`/`fingerprint`/`full`), karantina (`br-quar`), `rg_block`, `arp_heal`, syslog alarm iletimi (`alerting/syslog.py`), Streamlit dashboard (`dashboard/`) + daemon `approvals` onay akışı (`containment/approvals.py`).

### Sıradaki Adımlar
- [ ] **6.7 Cihaz türü sınıflandırma (`rogueguard/classify/`):**
  - `rules.py`: port, mDNS, OUI, vendor_class ile `{camera, printer, smart_plug, sensor, thermostat, unknown}` tahmini.
  - `llm.py`: Groq OpenAI-uyumlu API (`https://api.groq.com/openai/v1`), `temperature=0`, JSON `{label, confidence, reason}`, parmak izi hash önbelleği, 429'da `retry-after`. Anahtar `.env`'den okunur.
- [ ] **Adım 4 — Wazuh SIEM:** `wazuh` container (`images:ubuntu/24.04`, `security.nesting=true`, `limits.memory=5GiB`, `incusbr0` statik IP, proxy `8443 → 443`), `wazuh-docker` single-node, UDP 514 syslog, `lab/wazuh/` altında `local_decoder.xml` ve `local_rules.xml` (100200–100205, `<mitre><id>`).
- [ ] **Adım 7 — Deneyler (`experiments/`):**
  - `run_scenarios.py`: 3 profil (`allowlist`, `fingerprint`, `full`) × 8 senaryo (R1–R4, B1–B4) × 10 tekrar, kaldığı yerden devam edebilmeli, `results.csv`, arpwatch `journalctl` kıyaslaması.
  - `metrics.py`: tespit oranı, ortalama/medyan TTD ve TTC, yanlış pozitif, arpwatch sütunu.
  - LLM deneyi: 30–50 etiketli parmak izi JSON'u (canlı + `devices.yaml` varyantları), kurallar/LLM/hibrit doğruluğu, confusion matrix, gecikme, prompt injection testi.

---

## 7. Bilinen Tuzaklar

- **VM askıdan dönünce `incusbr0` IPv4'ünü kaybeder:** `sudo systemctl restart incus && incus exec rg-router -- networkctl reconfigure eth0`.
- **Incus aynı MAC'i iki container'a vermez:** MAC klonlayan rogue senaryolarında (R2/R3/R4) rogue kendi MAC'iyle başlar, MAC içeriden değiştirilir (`ip link set eth0 down; ip link set eth0 address <MAC>; ip link set eth0 up; networkctl reconfigure eth0`).
- **Python 3.14 pip:** VM `.venv`'de yeni paket gerekirse tek tek kur (`pip install <paket>`), toplu kurulum takılabiliyor.
- **`inventory.yaml` sadece VM'dedir** (gitignore'da); benzerlik tablosunu yenilemek için VM'de `.venv/bin/python -m experiments.similarity_table`.
