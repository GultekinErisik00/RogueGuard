"""Tüm keşif iş parçacıklarının ortak yazıcısı: gözlemleri kuyruğa alır, tek bir
thread'de SQLite'a yazar ve EventTracker ile new_device/changed_device olaylarını üretir.
(SQLite bağlantısı thread'ler arasında paylaşılamadığı için tek yazıcı kullanılır.)"""
import logging
import queue
import threading
from typing import Any, Callable

from rogueguard import db
from rogueguard.discovery.events import EventTracker

log = logging.getLogger("rogueguard.discovery")

EventHook = Callable[[str, str | None, str, dict[str, Any]], None]
ObservationHook = Callable[[str, str | None, str, dict[str, Any]], None]


class Recorder:
    def __init__(self, db_path: str, on_event: EventHook | None = None,
                 on_observation: ObservationHook | None = None) -> None:
        self._db_path = db_path
        self._queue: queue.Queue = queue.Queue()
        self._on_event = on_event
        self._on_observation = on_observation
        self._thread = threading.Thread(target=self._run, name="recorder", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def record(self, mac: str, ip: str | None, source: str, data: dict[str, Any]) -> None:
        self._queue.put((mac.lower(), ip, source, data))

    def stop(self) -> None:
        self._queue.put(None)
        self._thread.join(timeout=10)

    def _run(self) -> None:
        conn = db.connect(self._db_path)
        tracker = EventTracker(db.known_macs(conn))
        while (item := self._queue.get()) is not None:
            mac, ip, source, data = item
            db.add_observation(conn, mac, ip, source, data)
            if self._on_observation:
                try:
                    self._on_observation(mac, ip, source, data)
                except Exception:   # karar motoru hatası kaydı durdurmasın, ama görünür olsun
                    log.exception("on_observation hatası: %s %s", mac, source)
            for etype, edata in tracker.update(mac, ip, source, data):
                db.add_event(conn, mac, etype, edata)
                log.info("%s %s %s %s", etype, mac, ip, edata)
                if self._on_event:
                    self._on_event(etype, mac, ip, edata)
        conn.close()
