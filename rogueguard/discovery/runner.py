"""Keşif modülünü bir arada çalıştırır: pasif sniffer + aktif ARP/mDNS döngüsü +
router'daki MQTT yayın dinleyicisi + trafik penceresi. learn ve protect modları bunun üzerine kurulur."""
import logging
import threading
import time

from rogueguard.discovery.arp_scan import ArpDedup, active_loop
from rogueguard.discovery.recorder import EventHook, ObservationHook, Recorder
from rogueguard.discovery.router_tap import RouterTap
from rogueguard.discovery.sniffer import PacketHook, Sniffer

log = logging.getLogger("rogueguard.discovery")


class Discovery:
    def __init__(self, cfg: dict, on_event: EventHook | None = None,
                 packet_hooks: list[PacketHook] | None = None,
                 on_observation: ObservationHook | None = None) -> None:
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.recorder = Recorder(cfg["database"]["path"], on_event, on_observation)
        dedup = ArpDedup(cfg["discovery"]["arp_record_every"])
        self.sniffer = Sniffer(cfg, self.recorder, dedup, packet_hooks)
        self.tap = RouterTap(cfg, self.sniffer.record_publish)
        self._active = threading.Thread(target=active_loop, name="active",
                                        args=(cfg, self.recorder, dedup, self.stop_event),
                                        daemon=True)

    def start(self) -> None:
        self.recorder.start()
        self.sniffer.start()
        self.tap.start()
        self._active.start()
        log.info("keşif başladı: %s", self.cfg["network"]["iot_iface"])

    def run_for(self, duration: float | None) -> None:
        """`duration` saniye (None = sonsuza dek) çalış; trafik penceresini periyodik kapat."""
        window = self.cfg["discovery"]["traffic_window"]
        end = time.time() + duration if duration else None
        try:
            while not self.stop_event.is_set() and (end is None or time.time() < end):
                self.stop_event.wait(min(window, max(0.0, (end or 1e18) - time.time())))
                self.sniffer.flush_traffic()
        except KeyboardInterrupt:
            pass
        self.stop()

    def stop(self) -> None:
        self.stop_event.set()
        self.sniffer.stop()
        self.tap.stop()
        self.sniffer.flush_traffic()
        self.recorder.stop()
        log.info("keşif durdu")
