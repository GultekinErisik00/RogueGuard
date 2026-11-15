"""Gözlemlerden olay üretir: daha önce görülmemiş MAC → new_device; IP, hostname veya
DHCP izi değişen MAC → changed_device. Durum bellekte tutulur, açılışta DB'den tohumlanır."""
from typing import Any

from rogueguard.fingerprint.dhcp import fingerprint as dhcp_fingerprint

IP_SOURCES = {"arp", "dhcp"}
FP_MSG_TYPES = {"discover", "request"}


class EventTracker:
    def __init__(self, known: set[str]) -> None:
        self._known = set(known)
        self._state: dict[str, dict[str, Any]] = {}

    def update(self, mac: str, ip: str | None, source: str,
               data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        events: list[tuple[str, dict[str, Any]]] = []
        if mac not in self._known:
            self._known.add(mac)
            events.append(("new_device", {"ip": ip, "source": source}))

        new: dict[str, Any] = {}
        # IP sadece ARP ve DHCP'den izlenir: trafik paketindeki kaynak IP, router'ın
        # yönlendirdiği paketlerde başka cihazındır (yanlış "IP değişti" olur).
        if ip and source in IP_SOURCES:
            new["ip"] = ip
        # Parmak izi sadece DISCOVER/REQUEST'ten: RELEASE/ACK eksik option taşır.
        if source == "dhcp" and data.get("msg_type") in FP_MSG_TYPES:
            new.update({k: v for k, v in {"hostname": data.get("hostname"),
                                          "dhcp_fp": dhcp_fingerprint(data)}.items() if v})
        state = self._state.setdefault(mac, {})
        changes = {k: {"old": state[k], "new": v} for k, v in new.items()
                   if k in state and state[k] != v}
        state.update(new)
        if changes:
            events.append(("changed_device", changes))
        return events
