"""Aktif keşif: periyodik ARP taraması (scapy srp) ve br-iot'a mDNS PTR sorgusu.
ArpDedup, aynı (mac, ip) çiftinin her pakette tekrar yazılmasını önler."""
import logging
import threading
import time

from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether, sendp, srp

from rogueguard.discovery.recorder import Recorder

log = logging.getLogger("rogueguard.discovery")
MDNS_MAC, MDNS_IP = "01:00:5e:00:00:fb", "224.0.0.251"


class ArpDedup:
    """Yeni (mac, ip) çifti hemen, bilinen çift en fazla `every` saniyede bir kaydedilir."""

    def __init__(self, every: float) -> None:
        self._every = every
        self._last: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def should_record(self, mac: str, ip: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        with self._lock:
            last = self._last.get((mac, ip))
            if last is not None and now - last < self._every:
                return False
            self._last[(mac, ip)] = now
            return True


def arp_scan_once(iface: str, subnet: str) -> list[tuple[str, str]]:
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                 iface=iface, timeout=2, verbose=False)
    return [(r.hwsrc.lower(), r.psrc) for _, r in ans]


def mdns_query_once(iface: str, src_ip: str, types: list[str]) -> None:
    pkt = (Ether(dst=MDNS_MAC) / IP(src=src_ip, dst=MDNS_IP, ttl=255)
           / UDP(sport=5353, dport=5353)
           / DNS(qr=0, rd=0, qd=[DNSQR(qname=t, qtype="PTR") for t in types]))
    sendp(pkt, iface=iface, verbose=False)


def active_loop(cfg: dict, recorder: Recorder, dedup: ArpDedup, stop: threading.Event) -> None:
    net, disc = cfg["network"], cfg["discovery"]
    next_arp = next_mdns = 0.0
    while not stop.is_set():
        now = time.time()
        if now >= next_arp:
            for mac, ip in arp_scan_once(net["iot_iface"], net["iot_subnet"]):
                if dedup.should_record(mac, ip):
                    recorder.record(mac, ip, "arp", {"method": "scan"})
            next_arp = now + disc["arp_scan_interval"]
        if now >= next_mdns:
            mdns_query_once(net["iot_iface"], net["sensor_iot_ip"], disc["mdns_types"])
            next_mdns = now + disc["mdns_query_interval"]
        stop.wait(1)
