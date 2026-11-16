---
tags: [rogueguard, ara-degerlendirme, deney]
---
# R1 — İlk Ölçümler (16 Kasım 2026)

Haritası: [[RogueGuard]]. Teknik eşleme: [[ATT&CK Eşlemesi]].

**Senaryo R1:** hiçbir şey gizlemeyen rogue cihaz. `images:fedora/43` container'ı (meşru cihazlarda kullanılmayan imaj) `br-iot` köprüsüne bağlanır. `protect` çalışıyor, `detection_profile: fingerprint`.

## Sonuç
| Koşu | MAC | Tespit türü | RogueGuard tespit süresi (sn) | arpwatch `new station` (sn) |
|---|---|---|---|---|
| 1 | 10:66:6a:a8:d2:ef | unknown_device | 0.71 | ~8.7 |
| 2 | 10:66:6a:69:f5:e9 | unknown_device | 0.52 | 8.77 |
| 3 | 10:66:6a:37:05:0c | unknown_device | 0.49 | 6.26 |
| 4 | 10:66:6a:04:be:f3 | unknown_device | 0.46 | 8.76 |
| 5 | 10:66:6a:f0:86:ed | unknown_device | 0.44 | 9.24 |
| 6 | 10:66:6a:ad:8a:96 | unknown_device | 0.45 | 7.77 |

- **Tespit oranı:** 6/6, tür doğru (T1200 Hardware Additions, aksiyon `pending`).
- **Tespit süresi:** medyan 0.48 sn (0.44–0.71). Süre, container'ın başlatılmasından alarmın yazılmasına kadar.
- **arpwatch:** medyan 8.8 sn (6.3–9.2). 1. koşunun değeri saniye çözünürlüklü günlükten okundu.
- **Erişim:** rogue IP aldı (10.20.0.130) ama broker'a (TCP 1883) ulaşamadı; onaysız cihaz router'da sadece DHCP/DNS alır.

## Neden RogueGuard daha hızlı
RogueGuard cihazı ilk **DHCP DISCOVER** paketinde görür (IP almadan önce). arpwatch ise cihaz IP alıp ilk ARP paketini gönderene kadar bekler.

## Yanlış pozitif kontrolü (B1)
Aynı oturumda 6 meşru cihaz yeniden başlatıldı: hepsi DHCP paketlerini yeniden gönderdi, **0 alarm**.

## Ek: MAC kopyalama ve karantina (tek koşu)
Kurban (cam-01) açıkken Fedora rogue içeriden cam-01'in MAC'ine geçti.

| Adım | Süre (MAC değişiminden itibaren) |
|---|---|
| `impersonation` alarmı (T1036; farklı: hostname, option 55, vendor class) | 0.07 sn |
| Rogue `br-quar` köprüsüne taşındı | 0.20 sn |

- Rogue karantinada 10.20.1.130 aldı; broker'a ve kurbana ulaşamıyor.
- cam-01 `br-iot`'ta, `approved`, broker'a ulaşmaya devam ediyor (yanlış engelleme yok).
- Incus aynı MAC'i iki container'a vermediği için rogue önce kendi MAC'iyle bağlandı ve `unknown_device` alarmı da üretti.

## Ek: tarama ve ARP zehirleme (`full` profil)
Rogue: Fedora 43 + nmap + dsniff, `br-iot` üzerinde; kurban cam-01.

| Saldırı | Tespit | Aksiyon | Süre |
|---|---|---|---|
| Port taraması (`nmap -sT -p 1-300`) | `abnormal_scan` (T1046) | `rg_block` | tespit 0.30 sn, blok 0.42 sn (tarama başlangıcından) |
| ARP zehirleme (`arpspoof -t kurban ağ_geçidi`), 3 koşu | `arp_spoofing` (T1557.002) | karantina + ARP iyileştirme | tespitten karantinaya 0.25–0.31 sn |

- **İyileştirme bulgusu:** ilk denemede saldırgan karantinaya alındığı hâlde kurbanın ARP önbelleği zehirli kaldı ve kurban broker'a ulaşamadı. Doğru IP→MAC bağları yeniden duyurulunca kurban 1 sn içinde düzeldi. Yalnızca saldırganı ayırmak yetmiyor.
- **arpwatch:** ARP zehirlemeyi `changed ethernet address` / `flip flop` olarak aynı saniyede gördü; fark tespit hızında değil, RogueGuard'ın saldırganı ayırıp kurbanı düzeltmesinde.
- **Yanlış pozitif:** `full` profilde 6 meşru cihaz yeniden başlatılıp 3+ dakika izlendi, 0 alarm.

## Sınırlar
- 6 koşu, tek konfigürasyon; tam deney (3 konfigürasyon × 8 senaryo × 10 tekrar) Adım 7'de `experiments/run_scenarios.py` ile yapılacak.
- Karantina ölçümü tek koşu; `block` aksiyonu canlı denenmedi.
- Koşular elle betikle alındı; ölçümler `results.csv`'de değil.
