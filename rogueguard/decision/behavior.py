"""Davranış sapması (abnormal_behavior): onaylı bir cihaz, öğrenilmiş davranışından K ardışık
trafik penceresinde saparsa alarm. Sapma: envanterde olmayan hedefe bağlantı ya da öğrenilen
yayın hızının çok üstünde MQTT yayını. Sessizlik sapma sayılmaz (cihaz kapalı olabilir);
tek pencerelik sapma da sayılmaz (yanlış pozitif önlemi)."""
from typing import Any


class BehaviorMonitor:
    def __init__(self, windows: int, window_seconds: float, rate_factor: float,
                 rate_slack: int, ignore_ips: set[str]) -> None:
        self._k, self._seconds = windows, window_seconds
        self._factor, self._slack = rate_factor, rate_slack
        self._ignore = ignore_ips            # ağ geçidi ve sensör: DNS/DHCP/keşif cevapları
        self._streak: dict[str, int] = {}

    def deviations(self, inventory: dict[str, Any], traffic: dict[str, Any]) -> list[str]:
        found = []
        known = set(inventory["destinations"])
        new = sorted(d for d in traffic.get("destinations", [])
                     if d not in known and d.rsplit(":", 1)[0] not in self._ignore)
        if new:
            found.append("yeni hedef: " + ", ".join(new[:5]))
        expected = self._seconds / inventory["interval"] if inventory["interval"] else 0
        limit = self._factor * expected + self._slack
        if traffic.get("publishes", 0) > limit:
            found.append(f"yayın sayısı {traffic['publishes']} > beklenen üst sınır {limit:.0f}")
        return found

    def check(self, mac: str, inventory: dict[str, Any], traffic: dict[str, Any]) -> str | None:
        """Pencereyi değerlendirir; K ardışık sapmada gerekçeyi döndürür."""
        found = self.deviations(inventory, traffic)
        if not found:
            self._streak[mac] = 0
            return None
        self._streak[mac] = self._streak.get(mac, 0) + 1
        if self._streak[mac] < self._k:
            return None
        self._streak[mac] = 0
        return f"{self._k} ardışık pencerede sapma; " + "; ".join(found)
