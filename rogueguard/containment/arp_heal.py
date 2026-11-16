"""ARP zehirlemesinden sonra iyileştirme: saldırgan karantinaya alınsa da kurbanların ARP
önbelleği zehirli kalır (ağ geçidi için saldırganın MAC'ini tutar) ve kurban ağa çıkamaz.
Envanterdeki doğru IP→MAC bağları br-iot'a yayın (broadcast) ARP ile yeniden duyurulur."""
from scapy.all import ARP, Ether, sendp

BROADCAST = "ff:ff:ff:ff:ff:ff"
REPEAT = 2   # paket kaybına karşı


def heal_packets(bindings: list[tuple[str, str]]) -> list:
    """Her (ip, mac) bağı için gratuitous ARP isteği ve cevabı (ikisi de önbelleği günceller)."""
    packets = []
    for ip, mac in bindings:
        for op in (1, 2):
            packets.append(Ether(dst=BROADCAST) / ARP(op=op, hwsrc=mac, psrc=ip,
                                                      hwdst=BROADCAST, pdst=ip))
    return packets


def heal(iface: str, bindings: list[tuple[str, str]]) -> None:
    if bindings:
        sendp(heal_packets(bindings), iface=iface, count=REPEAT, verbose=False)
