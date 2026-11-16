"""ARP zehirleme tespiti (arp_spoofing, T1557.002): bir ARP paketi, envanterde başka bir MAC'e
ait olan IP'yi kendi MAC'iyle sahipleniyorsa (ör. "ağ geçidi 10.20.0.1 bende") zehirlemedir.
Bağ tablosu envanterdeki onaylı cihazların IP→MAC eşlemesidir (router ve sensör dahil)."""


def spoof_reason(hwsrc: str, psrc: str, owner_mac: str | None) -> str | None:
    """`psrc` IP'sinin envanterdeki sahibi `owner_mac` iken `hwsrc` onu sahipleniyorsa gerekçe."""
    if psrc == "0.0.0.0" or owner_mac is None or hwsrc.lower() == owner_mac.lower():
        return None
    return f"{psrc} envanterde {owner_mac} cihazına ait, ARP'de {hwsrc} sahipleniyor"
