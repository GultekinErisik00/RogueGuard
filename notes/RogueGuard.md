---
tags: [rogueguard, index]
---
# RogueGuard — Proje Haritası

Siber Güvenlik dönem projesi: izole lab ağındaki IoT cihazlarını keşfet, parmak izini çıkar, öğrenilmiş envanterle karşılaştır, sahte/taklitçi cihazı karantinaya al.

## Durum ve talimatlar
- [[PROGRESS]] — oturum günlüğü, tamamlanan adımlar, sıradaki iş
- [[CLAUDE]] — ajan talimatları, mimari, değerler (§3), yapılacaklar (§7)

## Ara değerlendirme (19 Kasım 2026) teslimleri
- [x] Adım 1–3: VM, köprüler, router, broker, 6 cihaz
- [x] 6.1 Keşif, 6.2 Öğrenme modu
- [x] 6.3 Karar motoru (unknown_device, impersonation)
- [x] [[Benzerlik Tablosu]]
- [x] [[ATT&CK Eşlemesi]]
- [x] [[LLM Planı]]
- [x] [[R1 İlk Ölçümler]]

## Rapor için
- [[Karşılaşılan Zorluklar]]
- Hocanın geri bildirimi: cihazlar farklı olmalı → [[Benzerlik Tablosu]]; Enterprise matrisi → [[ATT&CK Eşlemesi]]; LLM → [[LLM Planı]]

## Kod haritası
| Modül | Görev |
|---|---|
| `rogueguard/discovery/` | sniffer (ARP/DHCP/mDNS), aktif ARP taraması, router_tap (MQTT yayınları), olaylar |
| `rogueguard/fingerprint/` | dhcp, mdns, traffic, ports (nmap), profile, compare (benzerlik) |
| `rogueguard/learn.py` | öğrenme modu → `devices` approved, `inventory.yaml`, `rg_approved` |
| `rogueguard/containment/router.py` | rg-router nftables setleri |
| `lab/` | cihaz profilleri, ajan, router/host yapılandırması |
