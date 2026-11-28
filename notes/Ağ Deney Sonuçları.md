---
tags: [rogueguard, deney, ağ]
---
# Ağ Deney Sonuçları (7B)

Harita: [[RogueGuard]] · Kod: `experiments/scenarios.py`, `experiments/run_scenarios.py`, `experiments/outcome.py`, `experiments/metrics.py` · Ham çıktı: `experiments/results.csv` (gitignore'da, VM'de ve Mac'te)

## Kurulum
- **Matris:** 3 tespit profili (`allowlist`, `fingerprint`, `full`) × 8 senaryo × 10 tekrar = **240 koşu**, 27–28 Kasım 2026 gecesi (~6 saat). Wazuh kapalı.
- **Saldırılar:** R1 rogue hiçbir şey gizlemez · R2 kurbanın MAC'ini kopyalar (kurban kapalı) · R3 MAC + hostname + port/banner/mDNS/MQTT ajanı · R4 R3 + `arpspoof`. Rogue tabanı `images:fedora/43` (meşru cihazlarda kullanılmayan imaj).
- **Normal olaylar:** B1 cihaz restart · B2 IP değişimi (dnsmasq rezervasyonu + restart) · B3 yeni meşru cihaz + dashboard onayı · B4 sessiz süre.
- **Kurban rotasyonu:** tekrar numarasına göre cam-01, printer-01, plug-01, temp-01, thermo-01 (cam-02 ikiz olduğu için yok).
- **Her koşu sıfırdan:** rogue `clean` snapshot, rezervasyon silinir, `baseline.db` → `run.db`, `rg_block` boşalır, `protect --profile P` yeniden başlar, 20 sn dengelenme → `t0` → senaryo. Rogue senaryolarında tespitten sonra en az 30 sn gözlem (arpwatch'a adil süre); B'de 90 sn (B4 120 sn).
- **Ölçümler:** tespit, ilk alarm türü doğru mu, TTD (t0 → ilk alarm), TTC (t0 → karantina), yanlış pozitif (hedef dışı MAC'e alarm; B'de her alarm), yanlış karantinaya alınan meşru cihaz, aynı pencerede arpwatch.

## Bulgular
1. **Parmak izi şart.** `allowlist` (sadece MAC listesi) R1'i yakaladı ama MAC kopyalayan R2–R4'ün **hiçbirini** yakalamadı (0/30). `fingerprint` ve `full` 60/60 saldırıyı yakaladı, ilk alarm türü her seferinde doğru (`impersonation`, T1036).
2. **Hız:** TTD medyan 0.06–0.09 sn (en çok 0.11 sn), TTC (karantina, `br-quar`) medyan 0.18–0.21 sn (en çok 0.34 sn). t0 rogue'un DHCP'yi başlattığı an olduğu için alarm, rogue'un ilk DHCP paketlerinden hemen sonra geliyor.
3. **Yanlış pozitif yok.** 240 koşunun hiçbirinde meşru cihaza alarm ya da karantina yok; B1 (restart), B2 (IP değişimi, 30/30 koşuda IP DB'de yeni adrese taşındı) ve B4 (sessizlik) alarmsız geçti. B3'te yeni cihaz her seferinde `unknown_device` (T1200) + `pending` oldu, onay medyan ~2.0 sn'de router'a uygulandı.
4. **arpwatch kıyaslaması:**
   - R1 (yeni MAC): arpwatch da yakaladı ama medyan ~9 sn'de; RogueGuard 0.06 sn.
   - R2/R3 (MAC kopyası, fingerprint/full): arpwatch **0%**: kopya MAC, kurbanın bilinen IP–MAC çiftiyle görünüyor. (`allowlist` R2'de %50 uyarı verdi; nedeni ayrıca incelenmedi.)
   - R4 `allowlist`: rogue engellenmediği için `arpspoof` çalışabiliyor; arpwatch 10/10 (medyan 4.9 sn) uyarırken `allowlist` profili hiçbir şey görmedi. ARP koruması (`arp_guard.py`) sadece `full`'da açık.
   - B2: arpwatch meşru IP değişiminde %0–50 uyarı verdi (yanlış pozitif); RogueGuard 0.
5. **R4 ≈ R3 (fingerprint/full).** Rogue DHCP aşamasında ~0.2 sn'de karantinaya alındığı için `arpspoof` br-iot'ta hiç etkili olamadı; 20 koşunun hiçbirinde `arp_spoofing` alarmı çıkmadı. Yani R4'te ARP savunmasını değil, erken karantinayı ölçtük. ARP korumasının tek başına çalıştığını 6.3'teki canlı testten biliyoruz (onaysız MAC'le zehirleme → `arp_spoofing`, T1557.002).

## Sınırlılıklar
- Lab tek VM içinde, gecikmeler gerçek ağdan düşük; mutlak süreler değil, profiller arası fark ve arpwatch'a göre sıra anlamlı.
- Rogue, DHCP option 55/60 sırasını kopyalamıyor (R3+ yapılmadı). Option'ları da kopyalayan bir rogue'u sadece port/mDNS/yayın aralığı ayırabilir; thermo-01 gibi systemd-networkd kullanan kurbanlarda bu daha zor vaka.
- arpwatch durumu koşular arasında sıfırlanmıyor (kalıcı veritabanı). Aynı tekrarın üç profili arka arkaya koştuğu için arpwatch sütunu profiller arasında bağımsız değil; B2'de `allowlist` %50 / `full` %0 farkı profil etkisi değil, arpwatch'ın aynı IP–MAC çiftini ikinci kez görmesidir.
- Her hücre 10 tekrar; kurban rotasyonu yüzünden her kurban hücre başına 2 kez.

## Deney sırasında bulunan hata (rapor için)
İlk koşuda B2'de "IP taşındı" 30 koşunun sadece 22'sinde doğruydu (thermo-01 6/6, printer-01 2 kez başarısız). Sebep RogueGuard değil koşucuydu: B2'nin rezerve ettiği adres (10.20.0.190–199) önceki rogue koşularından kalan kiralardan birindeydi ve dnsmasq `not using configured address … because it is leased to …` diyerek rezervasyonu yok saydı; cihaz eski IP'sini geri aldı (yani o koşular pratikte B1 oldu). Düzeltme: rezervasyon yapılırken o IP'yi tutan kira da siliniyor (`lab_ops.lease_cleanup`, testli). 8 koşu yeniden koşuldu, 30/30 taşındı; yanlış pozitif yine 0.

## Tablolar
### Saldırılar (R1–R4)
| Profil | Senaryo | n | Tespit | Tür doğru | TTD ort/med (sn) | TTC ort/med (sn) | YP alarm | Meşru karantina | arpwatch | arpwatch TTD med |
|---|---|---|---|---|---|---|---|---|---|---|
| allowlist | R1 | 10 | 100% | 100% | 0.06 / 0.06 | — / — | 0 | 0 | 100% | 9.07 |
| allowlist | R2 | 10 | 0% | 0% | — / — | — / — | 0 | 0 | 50% | 8.91 |
| allowlist | R3 | 10 | 0% | 0% | — / — | — / — | 0 | 0 | 0% | — |
| allowlist | R4 | 10 | 0% | 0% | — / — | — / — | 0 | 0 | 100% | 4.85 |
| fingerprint | R1 | 10 | 100% | 100% | 0.07 / 0.07 | — / — | 0 | 0 | 100% | 8.75 |
| fingerprint | R2 | 10 | 100% | 100% | 0.06 / 0.06 | 0.20 / 0.18 | 0 | 0 | 0% | — |
| fingerprint | R3 | 10 | 100% | 100% | 0.08 / 0.08 | 0.21 / 0.21 | 0 | 0 | 0% | — |
| fingerprint | R4 | 10 | 100% | 100% | 0.08 / 0.09 | 0.21 / 0.20 | 0 | 0 | 0% | — |
| full | R1 | 10 | 100% | 100% | 0.06 / 0.06 | — / — | 0 | 0 | 100% | 8.99 |
| full | R2 | 10 | 100% | 100% | 0.06 / 0.06 | 0.20 / 0.18 | 0 | 0 | 0% | — |
| full | R3 | 10 | 100% | 100% | 0.09 / 0.09 | 0.22 / 0.21 | 0 | 0 | 0% | — |
| full | R4 | 10 | 100% | 100% | 0.08 / 0.08 | 0.20 / 0.19 | 0 | 0 | 0% | — |

### Normal olaylar (B1–B4)
| Profil | Senaryo | n | YP alarm (koşu) | Meşru karantina | arpwatch uyarısı | Not |
|---|---|---|---|---|---|---|
| allowlist | B1 | 10 | 0 (0) | 0 | 0% |  |
| allowlist | B2 | 10 | 0 (0) | 0 | 50% | IP taşındı 10/10 |
| allowlist | B3 | 10 | 0 (0) | 0 | 100% | unknown_device 100%, onay medyan 1.98 sn |
| allowlist | B4 | 10 | 0 (0) | 0 | 0% |  |
| fingerprint | B1 | 10 | 0 (0) | 0 | 0% |  |
| fingerprint | B2 | 10 | 0 (0) | 0 | 30% | IP taşındı 10/10 |
| fingerprint | B3 | 10 | 0 (0) | 0 | 100% | unknown_device 100%, onay medyan 2.00 sn |
| fingerprint | B4 | 10 | 0 (0) | 0 | 0% |  |
| full | B1 | 10 | 0 (0) | 0 | 0% |  |
| full | B2 | 10 | 0 (0) | 0 | 0% | IP taşındı 10/10 |
| full | B3 | 10 | 0 (0) | 0 | 100% | unknown_device 100%, onay medyan 1.99 sn |
| full | B4 | 10 | 0 (0) | 0 | 0% |  |
