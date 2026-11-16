"""br-iot köprüsünün port arayüzlerini (veth) dinler: ARP ve TCP SYN paketleri.
Host'un br-iot arayüzü cihazlar arası unicast çerçeveleri görmez (köprü onları sadece hedef
porta iletir); ARP zehirleme ve port taraması tam da böyle çerçevelerdir. Port arayüzlerini
dinlemek, gerçek bir anahtardaki SPAN (ayna) portunun karşılığıdır. Yeni container yeni port
açtığı için üyelik periyodik yenilenir. Sadece cihazdan gelen (giriş yönlü) çerçeveler işlenir."""
import logging
import os
import threading
import time
from typing import Any, Callable

from scapy.all import ARP, IP, TCP, AsyncSniffer, Ether, get_if_hwaddr

log = logging.getLogger("rogueguard.discovery")

BPF = "arp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
PACKET_OUTGOING = 4          # Linux AF_PACKET: host'tan container'a giden çerçeve
REFRESH_SECONDS = 2

ArpHook = Callable[[float, str, str, str, str], None]   # (ts, ether_src, hwsrc, psrc, pdst)
SynHook = Callable[[float, str, str, str, int], None]   # (ts, ether_src, src_ip, dst_ip, dport)


def bridge_ports(bridge: str) -> list[str]:
    try:
        return sorted(os.listdir(f"/sys/class/net/{bridge}/brif"))
    except FileNotFoundError:
        return []


class PortTap:
    def __init__(self, cfg: dict, on_arp: ArpHook, on_syn: SynHook) -> None:
        self._bridge = cfg["network"]["iot_iface"]
        self._own_mac = get_if_hwaddr(self._bridge).lower()
        self._on_arp, self._on_syn = on_arp, on_syn
        self._ports: list[str] = []
        self._sniffer: AsyncSniffer | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._refresh_loop, name="port-tap", daemon=True)

    def start(self) -> None:
        self._restart_if_changed()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._stop_sniffer()

    def _refresh_loop(self) -> None:
        while not self._stop.wait(REFRESH_SECONDS):
            self._restart_if_changed()

    def _restart_if_changed(self) -> None:
        ports = bridge_ports(self._bridge)
        if ports == self._ports:
            return
        self._stop_sniffer()
        self._ports = ports
        if ports:
            self._sniffer = AsyncSniffer(iface=ports, filter=BPF, prn=self._handle, store=False)
            self._sniffer.start()
        log.info("port-tap: %d köprü portu dinleniyor", len(ports))

    def _stop_sniffer(self) -> None:
        if self._sniffer is not None and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception:   # port o sırada silindiyse (container durdu) scapy hata verir
                log.debug("port-tap sniffer durdurulamadı", exc_info=True)
        self._sniffer = None

    def _handle(self, pkt: Any) -> None:
        if Ether not in pkt or getattr(pkt, "direction", None) == PACKET_OUTGOING:
            return
        src = pkt[Ether].src.lower()
        if src == self._own_mac:
            return
        try:
            if ARP in pkt:
                arp = pkt[ARP]
                self._on_arp(time.time(), src, arp.hwsrc.lower(), arp.psrc, arp.pdst)
            elif IP in pkt and TCP in pkt:
                self._on_syn(time.time(), src, pkt[IP].src, pkt[IP].dst, int(pkt[TCP].dport))
        except Exception:
            log.exception("port-tap paketi işlenemedi: %s", pkt.summary())
