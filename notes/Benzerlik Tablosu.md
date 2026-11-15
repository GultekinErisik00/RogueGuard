---
tags: [rogueguard, ara-degerlendirme, benzerlik]
---
# Benzerlik Tablosu

Hocanın 1. geri bildirimi: **cihazlar birbirinden farklı olmalı**. Haritası: [[RogueGuard]]. Ağırlıklar ve eşik `config.yaml` → `fingerprint`.

Kaynak: 15 Kasım 2026, 660 sn'lik `learn` sonrası canlı envanter. Yeniden üretmek için (VM'de):
```bash
.venv/bin/python -m experiments.similarity_table
```

## İkili benzerlik (0 = tamamen farklı, 1 = aynı)
Eşik: **0.6**. Meşru çiftler bunun altında olmalı; tek istisna bilinçli ikiz cam-01/cam-02.

| | cam-01 | cam-02 | plug-01 | printer-01 | temp-01 | thermo-01 |
|---|---|---|---|---|---|---|
| **cam-01** | — | 0.86 | 0.18 | 0.07 | 0.07 | 0.14 |
| **cam-02** | 0.86 | — | 0.18 | 0.07 | 0.07 | 0.14 |
| **plug-01** | 0.18 | 0.18 | — | 0.10 | 0.07 | 0.12 |
| **printer-01** | 0.07 | 0.07 | 0.10 | — | 0.07 | 0.07 |
| **temp-01** | 0.07 | 0.07 | 0.07 | 0.07 | — | 0.07 |
| **thermo-01** | 0.14 | 0.14 | 0.12 | 0.07 | 0.07 | — |

## Ölçülen parmak izleri
| Cihaz | OUI | option 55 | Portlar | mDNS | Yayın aralığı (sn) |
|---|---|---|---|---|---|
| cam-01 | `00:40:8c` | `[1, 3, 6, 12, 15, 28, 42]` | 80/tcp, 554/tcp | _http._tcp, _rtsp._tcp | 40 |
| cam-02 | `00:40:8c` | `[1, 3, 6, 12, 15, 28, 42]` | 80/tcp, 554/tcp | _http._tcp, _rtsp._tcp | 37 |
| plug-01 | `00:11:50` | `[1, 3, 6, 15, 28, 33, 42, 51, 58, 59]` | 80/tcp, 5355/tcp, 49153/tcp | _http._tcp | 10 |
| printer-01 | `00:1b:a9` | `[1, 28, 3, 6, 15, 42]` | 631/tcp, 5355/tcp, 9100/tcp | _ipp._tcp, _printer._tcp | 326 |
| temp-01 | `00:4b:12` | `[1, 2, 3, 6, 12, 15, 28, 42]` | — | — | 15 |
| thermo-01 | `44:61:32` | `[1, 3, 6, 12, 15, 33, 42, 114, 119, 120, 121]` | 80/tcp | _hap._tcp | 58 |

## Nasıl hesaplanıyor
`rogueguard/fingerprint/compare.py`, özellik başına skor × ağırlık:
- **Birebir:** OUI, hostname, option 55 listesi (sıra dahil), vendor class.
- **Jaccard:** açık portlar, mDNS servisleri, hedef ip:port kümesi (ağırlık 0.5).
- **Toleranslı:** yayın aralığı, %30 içinde ise eşleşir (ağırlık 0.5).

## Yorum
- Farklı DHCP istemcileri (udhcpc, dhclient, dhcpcd, systemd-networkd) farklı option 55 listeleri üretti; aynı istemci (udhcpc) bile `udhcpc_extra` ile ayrıştı (cam-01 vs temp-01).
- 5355/tcp (LLMNR), Debian imajlarındaki systemd-resolved'dan geliyor; gerçek cihazdaki gibi imajın yan etkisi.
- **Sınırlılık:** cam-01/cam-02 aynı model kamerayı temsil eder; sadece MAC'in son 3 baytı ve hostname farklı. Parmak izi tek başına aynı modelden iki cihazı ayıramaz → envanter MAC'i de kullanır, taklitçi tespiti (R2/R3) parmak izi + MAC birlikte değerlendirilerek yapılır.
- Test: `tests/test_learn_and_similarity.py` hem `lab/devices.yaml`'dan hem canlı envanterden bu koşulu doğrular.
