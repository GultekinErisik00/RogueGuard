---
tags: [rogueguard, rapor]
---
# RogueGuard — İlerleme Raporu (22 Kasım 2026)

**Proje:** Rogue IoT Device Detection and Containment. İzole bir lab ağındaki IoT cihazlarını keşfeder, parmak izini çıkarır, öğrenilmiş envanterle karşılaştırır; sahte ya da taklitçi cihazı otomatik olarak karantinaya alır veya engeller. Haritası: [[RogueGuard]].

## Lab ortamı
Tek bir Ubuntu 26.10 VM'i (Apple Silicon, VMware Fusion) içinde Incus container'ları:
- **3 köprü:** `br-iot` (cihazlar), `br-quar` (karantina), `br-svc` (servisler). Köprüler arası tek yol `rg-router`.
- **`rg-router`:** nftables + dnsmasq. Onaysız cihaz yalnızca DHCP/DNS alır; `rg_approved` broker'a ve internete çıkar; `rg_block` hiçbir yere çıkamaz.
- **MQTT broker** ve **6 meşru cihaz:** her biri farklı imaj, DHCP istemcisi, üretici OUI'si, hostname, port ve mDNS servisi kullanır (hocanın 1. geri bildirimi). cam-02, cam-01'in bilinçli ikizidir.

## Yazılım (Python, scapy, SQLite)
| Modül | Ne yapıyor |
|---|---|
| Keşif | ARP/DHCP/mDNS dinleme, aktif ARP taraması; router'da MQTT yayınları; köprü portlarında cihazlar arası ARP ve TCP SYN |
| Öğrenme (`learn`) | Ağı dinler, her cihazı nmap ile tarar, onaylı envanteri ve `rg_approved`'u oluşturur |
| Karar motoru (`protect`) | `unknown_device`, `impersonation`, `arp_spoofing`, `abnormal_scan`, `abnormal_behavior` alarmları ([[ATT&CK Eşlemesi]], Enterprise matrisi) |
| Kontrol altına alma | Karantina (`br-quar`), blok (`rg_block`), ARP zehirlemesinden sonra kurbanların ARP önbelleğini düzeltme |

45 birim testi geçiyor.

## Sonuçlar
- **Cihaz farklılığı:** meşru çiftlerin parmak izi benzerliği 0.07–0.18 (eşik 0.6); tek istisna ikiz kameralar, 0.86. → [[Benzerlik Tablosu]]
- **Canlı ölçümler** → [[R1 İlk Ölçümler]]

| Senaryo | Sonuç | Süre |
|---|---|---|
| R1: bilinmeyen cihaz (6 koşu) | 6/6 `unknown_device` | medyan 0.48 sn (arpwatch 8.8 sn) |
| MAC taklidi, kurban açık | `impersonation` → karantina | tespit 0.07 sn, karantina 0.20 sn |
| Port taraması | `abnormal_scan` → blok | tespit 0.30 sn, blok 0.42 sn |
| ARP zehirleme (3 koşu) | `arp_spoofing` → karantina + iyileştirme | tespitten karantinaya 0.25–0.31 sn |
| 6 meşru cihazın yeniden başlatılması | yanlış alarm yok | 0 alarm |

## Öne çıkan zorluklar → [[Karşılaşılan Zorluklar]]
- Linux köprüsü cihazlar arası unicast trafiği host'a iletmiyor; yayın aralığı ve ARP zehirlemesi görünmüyordu. Çözüm: router'da ve köprü portlarında dinleme (SPAN portu karşılığı).
- Saldırganı karantinaya almak kurbanı düzeltmedi; kurbanın ARP önbelleği zehirli kaldı. Çözüm: doğru ARP bağlarını yeniden duyurmak.
- Yeniden başlayan cihaz yeni IP alınca router izni eski IP'de kaldı. Çözüm: IP değişiminde izni taşımak (taklit şüphesi yoksa).

## Kalan işler
1. **6.5** syslog alarm iletimi, **6.6** Streamlit dashboard (onay akışı), **6.7** kural tabanlı ve LLM (Groq) cihaz türü tahmini → [[LLM Planı]]
2. **Adım 4:** Wazuh SIEM entegrasyonu
3. **Adım 7:** deneyler (3 profil × 8 senaryo × 10 tekrar), arpwatch kıyası, LLM doğruluk ve prompt injection deneyi
4. **1–5 Aralık:** final demo ve rapor
