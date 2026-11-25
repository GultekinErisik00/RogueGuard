# RogueGuard — Handoff (25 Kasım 2026)

Bu dosya, projenin tam olarak nerede kaldığını ve bir sonraki oturumda/adımda doğrudan nereden devam edileceğini özetler.
Genel kurallar ve mimari detaylar için `AGENTS.md`, oturum geçmişi için `PROGRESS.md` dosyasına bak.

---

## 1. Repo ve Ortam Durumu

- **GitHub Remote:** `https://github.com/GultekinErisik00/RogueGuard.git` (dal: `main`)
- **Test Durumu:** VM'de `61 passed` (`.venv/bin/python -m pytest -q`)
- **VM (`rogueguard-lab`):** Ubuntu 26.10 arm64, `ssh rogue` (`192.168.23.136`), şifresiz sudo aktif (`SUDO_OK`).
- **Çalışan Container'lar:** `rg-router`, `mqtt-broker`, `cam-01`, `cam-02`, `printer-01`, `plug-01`, `temp-01`, `thermo-01` (hepsi `clean` snapshot'lı).
- **VM Askı Notu:** Son kontrolde `rg-router` `eth0` (incusbr0) IPv4'ü düşmüştü. İnternet gereken ilk adımda (Wazuh/Groq) VM'de şu komutu çalıştır:
  ```bash
  ssh rogue 'sudo systemctl restart incus && incus exec rg-router -- networkctl reconfigure eth0'
  ```

---

## 2. Tamamlananlar

| Adım | Durum | Özet |
| --- | --- | --- |
| **Adım 1–3** | ✅ Bitti | VM, `br-iot`/`br-quar`/`br-svc`, host `inet rg_host` (+ nftables override), `rg-router` (nftables + dnsmasq), `mqtt-broker`, 6 farklı profilli IoT cihazı (`clean` snapshot). |
| **Adım 5** | ✅ Bitti | `arpwatch@br-iot`, VM `.venv` (Python 3.14), SQLite WAL şeması (`devices`, `observations`, `events`, `alerts`, `approvals`). |
| **6.1 Keşif** | ✅ Bitti | `sniffer.py`, `arp_scan.py`, `router_tap.py` (MQTT PUBLISH), `port_tap.py` (veth ARP/SYN), `recorder.py`, `events.py`. |
| **6.2 Öğrenme** | ✅ Bitti | `learn.py` + `nmap` + `inventory.yaml` + `rg_approved`. Benzerlik testi geçiyor (meşru çiftler 0.07–0.18, ikiz kameralar 0.86, eşik 0.6). |
| **6.3 Karar Motoru** | ✅ Bitti | `DecisionEngine` (`allowlist` / `fingerprint` / `full`), MITRE ATT&CK Enterprise eşlemesi (`attack_map.py`), `arp_guard.py`, `scan.py`, `behavior.py`. Canlı B1/R1/tarama/ARP zehirleme geçti. |
| **6.4 Karantina** | ✅ Bitti | `quarantine.py` (`br-quar`), `router.py` (`rg_approved`/`rg_block`), `actions.py` (`contained_at`), `arp_heal.py`. |
| **6.5 Alarm İletimi** | ✅ Bitti | `rogueguard/alerting/syslog.py` (UDP 514, Wazuh uyumlu syslog formatı + JSON yükü, `wazuh_ip: null` veya erişilemezken hatasız). `protect` `on_alert` zincirine bağlı. |
| **6.6 Dashboard + Onay** | ✅ Bitti | `rogueguard/containment/approvals.py` (`ApprovalWatcher`), `dashboard/{data,app}.py` (`@st.fragment(run_every="5s")`, `http://192.168.23.136:8501`), `db.py` `_match_dir_owner`. Canlı `approve`/`reject` → `rg_approved`/`rg_block` geçti. |
| **6.7 Sınıflandırıcı** | ✅ Bitti | `rogueguard/classify/{rules,llm}.py` (`openai/gpt-oss-20b`, parmak izi hash önbelleği, 429 `retry-after`, hibrit) + dashboard tahmini tür sütunu. Canlı Groq 6/6 doğru (0.40–0.71 sn), önbellek doğrulandı. |
| **Adım 4 — Wazuh SIEM** | ✅ Bitti | `wazuh` container (`10.160.244.10`, `wazuh-docker v4.14.11`, unprivileged, 5 GiB RAM, `https://192.168.23.136:8443`), `lab/wazuh/{local_decoder.xml,local_rules.xml,setup_wazuh.sh}`. 5/5 `wazuh-logtest` + canlı UDP 514 → OpenSearch `wazuh-alerts-*` doğrulandı. |

---

## 3. Tam Kaldığımız Yer → Sıradaki Adımlar

### 1. Sırada: **Adım 7 — Deneyler (`experiments/`)**
- `experiments/run_scenarios.py`: 3 profil (`allowlist`, `fingerprint`, `full`) × 8 senaryo (R1–R4, B1–B4) × 10 tekrar, kaldığı yerden devam edebilmeli, `experiments/results.csv`, `arpwatch@br-iot` `journalctl` kıyaslaması (Wazuh kapalı, `tmux` içinde).
- `experiments/metrics.py`: Konfigürasyon × senaryo tespit oranı, ortalama/medyan TTD ve TTC, yanlış pozitif, arpwatch sütunu.
- LLM deneyi: 30–50 etiketli parmak izi JSON'u + kural / LLM / hibrit doğruluk + confusion matrix + gecikme + prompt injection testi.

---

## 4. Hızlı Başlangıç Komutları

```bash
# 1) VM erişimini doğrula
ssh rogue 'hostname && whoami && sudo -n true && echo SUDO_OK'

# 2) Mac → VM senkronize et (data/ HARİÇ!)
rsync -a --exclude .venv --exclude .git --exclude .obsidian --exclude .agents --exclude data ./ rogue:~/rogueguard/

# 3) VM'de testleri çalıştır
ssh rogue 'cd ~/rogueguard && .venv/bin/python -m pytest -q'
```
