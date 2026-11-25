"""Alarm iletimi (6.5): karar motorunun ürettiği alarmları UDP 514 üzerinden syslog (Wazuh)
sunucusuna JSON formatında gönderir. wazuh_ip boşsa veya hedef erişilemezse hata vermeden
sessizce geçer; daemon'u durdurmaz."""
import json
import logging
from logging.handlers import SysLogHandler
import sqlite3
from typing import Any, Mapping

log = logging.getLogger("rogueguard.alerting")

SYSLOG_PORT = 514
SYSLOG_FORMAT = "%(asctime)s rogueguard-lab rogueguard: %(message)s"
SYSLOG_DATEFMT = "%b %d %H:%M:%S"
PAYLOAD_FIELDS = ("type", "mac", "ip", "severity", "attack_id", "action", "reason")


def build_payload(alert: Mapping[str, Any]) -> str:
    """Alarm satırından Wazuh JSON_Decoder'ın beklediği JSON yükünü üretir."""
    body = {k: alert[k] if k in alert else None for k in PAYLOAD_FIELDS}
    return json.dumps(body, ensure_ascii=False, sort_keys=True)


class _QuietSysLogHandler(SysLogHandler):
    """Wazuh kapalıyken/erişilemezken stderr'e traceback dökmeden OSError yakalar."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record) + "\x00"
            prio = f"<{self.encodePriority(self.facility, self.mapPriority(record.levelname))}>"
            data = (prio + msg).encode("utf-8")
            self.socket.sendto(data, self.address)
        except OSError as exc:
            log.debug("syslog gönderilemedi (%s): %s", self.address, exc)


class SyslogForwarder:
    def __init__(self, cfg: dict[str, Any], port: int | None = None,
                 handler: logging.Handler | None = None) -> None:
        self._host = cfg.get("network", {}).get("wazuh_ip")
        self._port = port or cfg.get("alerting", {}).get("syslog_port", SYSLOG_PORT)
        self._handler: logging.Handler | None = handler
        if self._handler is None and self._host:
            try:
                self._handler = _QuietSysLogHandler(address=(self._host, self._port))
            except OSError as exc:
                log.warning("syslog başlatılamadı (%s:%s): %s", self._host, self._port, exc)
                self._handler = None
        if self._handler is not None:
            self._handler.setFormatter(logging.Formatter(SYSLOG_FORMAT, datefmt=SYSLOG_DATEFMT))

    @property
    def enabled(self) -> bool:
        return self._handler is not None

    def send(self, alert: Mapping[str, Any]) -> bool:
        """Alarm sözlüğünü syslog ile gönderir; kapalıysa veya hata olursa False döner."""
        if self._handler is None:
            return False
        payload = build_payload(alert)
        record = logging.LogRecord(
            name="rogueguard", level=logging.WARNING, pathname="", lineno=0,
            msg=payload, args=(), exc_info=None,
        )
        try:
            self._handler.emit(record)
            return True
        except OSError as exc:
            log.debug("syslog gönderim hatası: %s", exc)
            return False

    def on_alert(self, conn: sqlite3.Connection, alert_id: int) -> None:
        """DecisionEngine `on_alert` kancası: alarm satırını okuyup syslog'a iletir."""
        if not self.enabled:
            return
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if row is not None:
            self.send(dict(row))

    def close(self) -> None:
        if self._handler is not None:
            self._handler.close()
            self._handler = None
