"""Pasif keşif: br-iot üzerinde tek bir scapy sniff'i ile ARP, DHCP (option 12/55/60/61),
mDNS (5353) ve trafik örneği toplar. Host'un kendi paketleri yok sayılır."""
import ipaddress
import logging
import threading
import time
from typing import Any, Callable

from scapy.all import ARP, BOOTP, DHCP, DNS, IP, TCP, UDP, AsyncSniffer, Ether, get_if_hwaddr

from rogueguard.discovery.arp_scan import ArpDedup
from rogueguard.discovery.recorder import Recorder
from rogueguard.fingerprint import dhcp as dhcp_fp
from rogueguard.fingerprint import mdns as mdns_fp
from rogueguard.fingerprint.traffic import TrafficWindow

log = logging.getLogger("rogueguard.discovery")
PacketHook = Callable[[Any], None]


def _mac_from_chaddr(chaddr: bytes) -> str:
    return ":".join(f"{b:02x}" for b in chaddr[:6])


def _is_unicast(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_multicast or ip == "255.255.255.255" or ip.endswith(".255"))


class Sniffer:
    def __init__(self, cfg: dict, recorder: Recorder, dedup: ArpDedup,
                 extra_hooks: list[PacketHook] | None = None) -> None:
        self._iface = cfg["network"]["iot_iface"]
        self._own_mac = get_if_hwaddr(self._iface).lower()
        self._recorder = recorder
        self._dedup = dedup
        self._traffic = TrafficWindow()
        self._lock = threading.Lock()
        self._hooks = extra_hooks or []  # 6.3: arp_guard gibi modüller ham paketi de görür
        self._sniffer = AsyncSniffer(iface=self._iface, filter="arp or ip",
                                     prn=self._handle, store=False)

    def start(self) -> None:
        self._sniffer.start()

    def stop(self) -> None:
        self._sniffer.stop()

    def flush_traffic(self) -> None:
        with self._lock:
            summaries = self._traffic.flush()
        for mac, ip, data in summaries:
            self._recorder.record(mac, ip, "traffic", data)

    # --- paket işleme -----------------------------------------------------------
    def _handle(self, pkt: Any) -> None:
        if Ether not in pkt or pkt[Ether].src.lower() == self._own_mac:
            return
        for hook in self._hooks:
            hook(pkt)
        try:
            if ARP in pkt:
                self._on_arp(pkt)
            elif DHCP in pkt:
                self._on_dhcp(pkt)
            elif UDP in pkt and pkt[UDP].sport == 5353 and DNS in pkt:
                self._on_mdns(pkt)
            elif IP in pkt:
                self._on_traffic(pkt)
        except Exception:  # tek bozuk paket sniff'i durdurmasın
            log.exception("paket işlenemedi: %s", pkt.summary())

    def _on_arp(self, pkt: Any) -> None:
        arp = pkt[ARP]
        if arp.psrc == "0.0.0.0":  # ARP probe (adres çakışma testi)
            return
        mac = arp.hwsrc.lower()
        if self._dedup.should_record(mac, arp.psrc):
            self._recorder.record(mac, arp.psrc, "arp", {
                "method": "passive", "op": int(arp.op), "pdst": arp.pdst,
                "gratuitous": arp.psrc == arp.pdst})

    def _on_dhcp(self, pkt: Any) -> None:
        bootp = pkt[BOOTP]
        mac = _mac_from_chaddr(bytes(bootp.chaddr))
        parsed = dhcp_fp.parse_options(pkt[DHCP].options)
        if bootp.op == 2:  # sunucudan: ACK ile IP→MAC bağı
            if parsed.get("msg_type") != "ack":
                return
            self._recorder.record(mac, bootp.yiaddr, "dhcp",
                                  {"msg_type": "ack", "server": pkt[IP].src})
            return
        ip = bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else parsed.get("requested_addr")
        self._recorder.record(mac, ip, "dhcp", parsed)

    def _on_mdns(self, pkt: Any) -> None:
        dns = pkt[DNS]
        if not dns.qr:  # sadece cevaplar/duyurular
            return
        parsed = mdns_fp.parse_records(mdns_fp.records_from_dns(dns))
        if parsed["services"] or parsed["hostname"]:
            self._recorder.record(pkt[Ether].src, pkt[IP].src, "mdns", parsed)

    def _on_traffic(self, pkt: Any) -> None:
        ip = pkt[IP]
        if not _is_unicast(ip.dst):
            return
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        dport = int(l4.dport) if l4 is not None else None
        proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else str(ip.proto)
        payload_len = len(l4.payload) if l4 is not None else 0
        with self._lock:
            self._traffic.add(time.time(), pkt[Ether].src.lower(), ip.src, ip.dst,
                              dport, proto, payload_len)
