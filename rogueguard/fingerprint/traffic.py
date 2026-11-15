"""Trafik örneği: MAC başına pencere içindeki hedef ip:port kümesi, paket sayısı ve
MQTT yayınları arasındaki süre. Pencere bitince özet 'traffic' gözlemi olarak yazılır.
Yayınlar add_publish() ile gelir (router_tap.py: router'da yakalanan MQTT PUBLISH)."""
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _MacStats:
    ip: str | None = None
    packets: int = 0
    destinations: set[str] = field(default_factory=set)
    publish_gaps: list[float] = field(default_factory=list)
    publishes: int = 0


class TrafficWindow:
    def __init__(self) -> None:
        self._stats: dict[str, _MacStats] = defaultdict(_MacStats)
        # Son yayın zamanı pencereler arası korunur: 300 sn'lik yayıncı (yazıcı) da ölçülür.
        self._last_publish: dict[str, float] = {}

    def add(self, ts: float, mac: str, src_ip: str, dst_ip: str, dport: int | None,
            proto: str, payload_len: int) -> None:
        st = self._stats[mac]
        st.ip = src_ip
        st.packets += 1
        if dport is not None:
            st.destinations.add(f"{dst_ip}:{dport}/{proto}")

    def add_publish(self, ts: float, mac: str, src_ip: str, dst_ip: str, dport: int) -> None:
        st = self._stats[mac]
        st.ip = src_ip
        st.destinations.add(f"{dst_ip}:{dport}/tcp")
        st.publishes += 1
        if mac in self._last_publish:
            st.publish_gaps.append(ts - self._last_publish[mac])
        self._last_publish[mac] = ts

    def flush(self) -> list[tuple[str, str | None, dict[str, Any]]]:
        """Pencereyi kapat: [(mac, ip, özet)] döndür ve sıfırla."""
        out = []
        for mac, st in self._stats.items():
            gaps = st.publish_gaps
            out.append((mac, st.ip, {
                "packets": st.packets,
                "destinations": sorted(st.destinations),
                "publishes": st.publishes,
                "publish_interval_median": statistics.median(gaps) if gaps else None,
            }))
        self._stats = defaultdict(_MacStats)
        return out
