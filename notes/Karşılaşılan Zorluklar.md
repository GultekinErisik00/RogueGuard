---
tags: [rogueguard, rapor]
---
# Karşılaşılan Zorluklar

Raporun "karşılaşılan zorluklar" bölümü için. Ayrıntılı ve güncel liste: [[PROGRESS#Karşılaşılan sorunlar]]. Haritası: [[RogueGuard]].

![[PROGRESS#Karşılaşılan sorunlar]]

## Keşif ve parmak izi aşamasında
- **Yanlış `changed_device` alarmları (6.1).** Cihaz kapanırken gönderdiği DHCP RELEASE eksik option taşıyordu → "parmak izi değişti" sanıldı. Router'ın yönlendirdiği paketlerdeki kaynak IP başka cihazındı → "router IP değişti" sanıldı. Çözüm: parmak izi sadece DISCOVER/REQUEST'ten, IP sadece ARP/DHCP'den izleniyor. Testle korunuyor.
- **Yayın aralığı görünmüyordu (6.2).** Linux köprüsü, cihaz→router unicast çerçevelerini host'un `br-iot` arayüzüne iletmiyor; host sniffer'ı MQTT yayınlarını göremiyordu. Çözüm: rg-router'ın eth1'inde `tcpdump` ile sadece MQTT PUBLISH yakalanıp trafik penceresine besleniyor (`discovery/router_tap.py`).
- **Seyrek yayıncı ölçülemiyordu.** 300 sn'de bir yayın yapan yazıcı, 60 sn'lik pencerede iki yayın üretmiyordu. Çözüm: son yayın zamanı pencereler arası tutuluyor.

## Karar ve karantina aşamasında
- **Köprü unicast'i host'a iletmiyor (ikinci kez).** ARP zehirleme paketleri kurbana unicast gider; host'un `br-iot` arayüzünden görünmez. Çözüm: köprü port arayüzlerini dinlemek (`discovery/port_tap.py`), gerçek anahtardaki SPAN portunun karşılığı.
- **Karantina kurbanı düzeltmiyor.** Saldırgan `br-quar`'a taşındıktan sonra kurbanın ARP önbelleği zehirli kaldı. Çözüm: karantinadan sonra doğru ARP bağlarını yeniden duyurmak (`containment/arp_heal.py`).
- **Incus aynı MAC'i iki container'a vermiyor.** MAC kopyalayan rogue, MAC'i içeriden değiştiriyor; karantina kodu bu yüzden çalışma anındaki MAC'e bakıyor.
- **Yeniden başlayan cihaz yeni IP alınca broker'a ulaşamadı** (`rg_approved` eski IP'de kaldı). Çözüm: DHCP ACK'te seti güncelleyen kanca; taklit şüphesi varsa güncellenmez.
