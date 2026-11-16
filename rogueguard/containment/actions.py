"""Karar motorunun yazdığı alarmın aksiyonunu uygular (alarm ≠ aksiyon):
pending → dokunma (onaysız cihaz router'da zaten sadece DHCP/DNS alır);
quarantine → container'ı br-quar'a taşı (ARP zehirlemesinde ardından doğru ARP bağlarını
yeniden duyur); block → IP'yi rg_block'a ekle.
Başarılı olursa alerts.contained_at yazılır (tespit→karantina süresi buradan ölçülür)."""
import logging
import sqlite3
import time
from typing import Callable

from rogueguard.containment.quarantine import Quarantine
from rogueguard.containment.router import Router

log = logging.getLogger("rogueguard.containment")


class Containment:
    def __init__(self, router: Router, quarantine: Quarantine,
                 clock: Callable[[], float] = time.time,
                 healer: Callable[[list[tuple[str, str]]], None] | None = None) -> None:
        self._router, self._quarantine, self._clock = router, quarantine, clock
        self._healer = healer    # arp_heal.heal; testlerde sahte

    def apply(self, conn: sqlite3.Connection, alert_id: int) -> None:
        alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        device = conn.execute("SELECT * FROM devices WHERE mac=?", (alert["mac"],)).fetchone()
        if alert["action"] == "quarantine":
            done = self._quarantine_device(conn, alert, device)
        elif alert["action"] == "block":
            done = self._block_device(conn, alert, device)
        else:
            return
        if not done:
            return
        conn.execute("UPDATE alerts SET contained_at=? WHERE id=?", (self._clock(), alert_id))
        if alert["type"] == "arp_spoofing" and self._healer:
            self._heal(conn)

    def _heal(self, conn: sqlite3.Connection) -> None:
        """Saldırgan ayrıldıktan sonra kurbanların zehirli ARP önbelleğini düzeltir."""
        bindings = [(r["ip"], r["mac"]) for r in conn.execute(
            "SELECT ip, mac FROM devices WHERE status='approved' AND ip IS NOT NULL")]
        self._healer(bindings)
        log.info("ARP iyileştirme: %d bağ yeniden duyuruldu", len(bindings))

    def _quarantine_device(self, conn, alert, device) -> bool:
        name = self._quarantine.isolate(alert["mac"], device["ip"] if device else None)
        if not name:
            log.error("karantina: %s MAC'li çalışan container bulunamadı", alert["mac"])
            return False
        log.warning("KARANTINA %s (%s) → br-quar", name, alert["mac"])
        # MAC taklidinde `devices` satırı kurbanındır; kurbanın durumu değiştirilmez.
        if alert["type"] != "impersonation":
            self._set_status(conn, device, "quarantined")
        return True

    def _block_device(self, conn, alert, device) -> bool:
        ip = alert["ip"] or (device["ip"] if device else None)
        if not ip:
            log.error("blok: %s için IP bilinmiyor", alert["mac"])
            return False
        self._router.add(self._router.block_set, ip)
        log.warning("BLOK %s (%s) → rg_block", ip, alert["mac"])
        self._set_status(conn, device, "blocked")
        return True

    def _set_status(self, conn, device, status: str) -> None:
        """Cihazın durumunu yazar; onaylıysa IP'sini rg_approved'dan çıkarır."""
        if device is None:
            return
        if device["status"] == "approved" and device["ip"] in self._router.members(
                self._router.approved_set):
            self._router.remove(self._router.approved_set, device["ip"])
        conn.execute("UPDATE devices SET status=? WHERE mac=?", (status, device["mac"]))
