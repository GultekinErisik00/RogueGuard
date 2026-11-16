"""Tarama tespiti (abnormal_scan, T1046): bir MAC kısa pencerede çok sayıda farklı adrese
ARP sorgusu gönderirse (ağ süpürme) ya da çok sayıda farklı ip:port'a TCP SYN gönderirse
(port taraması) tarama sayılır. Meşru IoT cihazı sadece ağ geçidine ve broker'a konuşur."""
from collections import defaultdict, deque


class ScanDetector:
    def __init__(self, window: float, arp_targets: int, syn_targets: int) -> None:
        self._window = window
        self._limits = {"arp": arp_targets, "syn": syn_targets}
        self._seen: dict[tuple[str, str], deque] = defaultdict(deque)   # (mac, tür) → (ts, hedef)

    def add(self, kind: str, ts: float, mac: str, target: str) -> str | None:
        """Gözlemi ekler; eşik aşıldıysa alarm gerekçesini, aşılmadıysa None döndürür."""
        events = self._seen[(mac, kind)]
        events.append((ts, target))
        while events and events[0][0] < ts - self._window:
            events.popleft()
        distinct = len({t for _, t in events})
        if distinct < self._limits[kind]:
            return None
        events.clear()   # aynı tarama için tekrar tekrar tetiklenmesin
        what = "ARP sorgusu (ağ süpürme)" if kind == "arp" else "TCP SYN (port taraması)"
        return f"{self._window:.0f} sn içinde {distinct} farklı hedefe {what}"
