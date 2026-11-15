---
tags: [rogueguard, ara-degerlendirme, attack]
---
# ATT&CK Eşlemesi (Enterprise)

Hocanın 2. geri bildirimi: **ICS değil Enterprise matrisi** kullanılır. Kaynak: [[CLAUDE]] §5. Haritası: [[RogueGuard]].

| Tespit türü | Teknik | Taktik | Önem | Aksiyon |
|---|---|---|---|---|
| `unknown_device` | T1200 Hardware Additions | Initial Access | orta | `pending`; engelleme yok, dashboard'dan onay |
| `impersonation` | T1036 Masquerading | Defense Evasion | yüksek | karantina (`br-quar`) |
| `arp_spoofing` | T1557.002 ARP Cache Poisoning | Credential Access, Collection | yüksek | karantina |
| `abnormal_scan` | T1046 Network Service Discovery | Discovery | yüksek | `rg_block` |
| `abnormal_behavior` | — (karşılığı yok) | — | yüksek | `rg_block` |

## Neden bu aksiyonlar
- **Karantina vs. blok:** ARP spoofing aynı köprüde L2'de olur, router'dan geçmez; nftables onu durduramaz. Bu yüzden cihaz `br-quar` köprüsüne taşınır. Tarama ve anormal davranış router'dan geçtiği için `rg_block` yeterli.
- **`unknown_device` engellenmez:** yeni meşru cihaz (senaryo B3) yanlışlıkla kesilmesin diye; zaten onaysız cihaz router'da sadece DHCP/DNS alabilir.

## Rogue seviyeleriyle ilişki
| Senaryo | Beklenen tespit |
|---|---|
| R1 hiçbir şey gizlemez | `unknown_device` (T1200) |
| R2 kurbanın MAC'ini kopyalar | `impersonation` (T1036) |
| R3 MAC + hostname + port + mDNS | `impersonation` (DHCP izi, yayın aralığı farkı) |
| R4 R3 + arpspoof | `arp_spoofing` (T1557.002) |
