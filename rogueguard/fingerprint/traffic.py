"""Trafik örneği: MAC başına pencere içindeki hedef ip:port kümesi, paket sayısı ve
MQTT yayınları arasındaki süre. Pencere bitince özet 'traffic' gözlemi olarak yazılır."""
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

MQTT_PORT = 1883


@dataclass
class _MacStats:
    ip: str | None = None
    packets: int = 0
    destinations: set[str] = field(default_factory=set)
    publish_times: list[float] = field(default_factory=list)


class TrafficWindow:
    def __init__(self) -> None:
        self._stats: dict[str, _MacStats] = defaultdict(_MacStats)

    def add(self, ts: float, mac: str, src_ip: str, dst_ip: str, dport: int | None,
            proto: str, payload_len: int) -> None:
        st = self._stats[mac]
        st.ip = src_ip
        st.packets += 1
        if dport is not None:
            st.destinations.add(f"{dst_ip}:{dport}/{proto}")
        if proto == "tcp" and dport == MQTT_PORT and payload_len > 0:
            st.publish_times.append(ts)

    def flush(self) -> list[tuple[str, str | None, dict[str, Any]]]:
        """Pencereyi kapat: [(mac, ip, özet)] döndür ve sıfırla."""
        out = []
        for mac, st in self._stats.items():
            gaps = [b - a for a, b in zip(st.publish_times, st.publish_times[1:])]
            out.append((mac, st.ip, {
                "packets": st.packets,
                "destinations": sorted(st.destinations),
                "publishes": len(st.publish_times),
                "publish_interval_median": statistics.median(gaps) if gaps else None,
            }))
        self._stats = defaultdict(_MacStats)
        return out
