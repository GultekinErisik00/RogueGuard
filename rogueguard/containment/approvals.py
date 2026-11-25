"""Dashboard onay akışı (6.6): Streamlit'in `approvals` tablosuna yazdığı approve/reject
kararlarını daemon tarafında okuyup uygular. SQLite tek iletişim kanalıdır; dashboard
router'a veya `devices` tablosuna doğrudan dokunmaz."""
import json
import logging
import sqlite3
import threading
import time
from typing import Any, Callable

from rogueguard import db
from rogueguard.containment.router import Router
from rogueguard.fingerprint import profile

log = logging.getLogger("rogueguard.approvals")

POLL_SECONDS = 2.0


def apply_pending(conn: sqlite3.Connection, router: Router,
                  clock: Callable[[], float] = time.time) -> int:
    """`applied_at IS NULL` olan tüm onay kararlarını sırayla uygular; uygulanan sayıyı döner."""
    rows = conn.execute(
        "SELECT id, mac, decision FROM approvals WHERE applied_at IS NULL ORDER BY id"
    ).fetchall()
    applied = 0
    for row in rows:
        mac, decision = row["mac"].lower(), row["decision"]
        dev = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        if dev is None:
            log.warning("onay atlandı: %s devices tablosunda yok", mac)
        elif decision == "approve":
            _approve_device(conn, router, dev, clock())
            applied += 1
        elif decision == "reject":
            _reject_device(conn, router, dev)
            applied += 1
        else:
            log.warning("bilinmeyen onay kararı (%s): %s", mac, decision)
        conn.execute("UPDATE approvals SET applied_at=? WHERE id=?", (clock(), row["id"]))
    return applied


def _approve_device(conn: sqlite3.Connection, router: Router,
                    dev: sqlite3.Row, now: float) -> None:
    """Cihazı onaylar; gözlemlerden eksik parmak izi alanlarını doldurup rg_approved'a ekler."""
    mac = dev["mac"]
    prof = profile.build_from_observations(conn, mac)
    ip = dev["ip"] or prof["ip"]
    hostname = dev["hostname"] or prof["hostname"]
    dhcp_fp = json.dumps({"opt55": prof["opt55"], "vendor_class": prof["vendor_class"]},
                         sort_keys=True) if (prof["opt55"] or prof["vendor_class"]) else dev["dhcp_fp"]
    mdns = json.dumps(prof["mdns"], sort_keys=True) if prof["mdns"] else (dev["mdns"] or "[]")
    dests = (json.dumps(prof["destinations"], sort_keys=True)
             if prof["destinations"] else (dev["destinations"] or "[]"))
    interval = prof["interval"] if prof["interval"] is not None else dev["publish_interval"]
    ports = dev["ports"] or "[]"

    conn.execute(
        "UPDATE devices SET ip=?, hostname=?, dhcp_fp=?, ports=?, mdns=?, destinations=?, "
        "publish_interval=?, status='approved', last_seen=? WHERE mac=?",
        (ip, hostname, dhcp_fp, ports, mdns, dests, interval, now, mac),
    )
    if ip:
        if ip in router.members(router.block_set):
            router.remove(router.block_set, ip)
        router.add(router.approved_set, ip)
    log.info("ONAYLANDI %s (%s) → rg_approved", mac, ip)


def _reject_device(conn: sqlite3.Connection, router: Router, dev: sqlite3.Row) -> None:
    """Cihazı reddeder: blocked durumuna alır ve IP'sini rg_block'a ekler."""
    mac, ip = dev["mac"], dev["ip"]
    conn.execute("UPDATE devices SET status='blocked' WHERE mac=?", (mac,))
    if ip:
        if ip in router.members(router.approved_set):
            router.remove(router.approved_set, ip)
        router.add(router.block_set, ip)
    log.warning("REDDEDİLDİ %s (%s) → rg_block", mac, ip)


class ApprovalWatcher:
    """Daemon çalışırken `approvals` tablosunu arka planda periyodik kontrol eder."""

    def __init__(self, db_path: str, router: Router, interval: float = POLL_SECONDS) -> None:
        self._db_path = db_path
        self._router = router
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="approvals", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        conn = db.connect(self._db_path)
        try:
            while not self._stop.is_set():
                try:
                    apply_pending(conn, self._router)
                except Exception:
                    log.exception("approvals işlenirken hata")
                self._stop.wait(self._interval)
        finally:
            conn.close()
