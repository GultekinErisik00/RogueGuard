"""6.5 testleri: syslog alarm iletimi — JSON yükü, syslog başlık formatı, yerel UDP
soketine gerçek gönderim ve wazuh_ip yokken/kapalıyken hata vermeme."""
import json
import logging
import re
import socket

from rogueguard import db
from rogueguard.alerting.syslog import SyslogForwarder, build_payload


SAMPLE_ALERT = {
    "type": "arp_spoofing",
    "mac": "02:00:00:aa:bb:cc",
    "ip": "10.20.0.150",
    "severity": "high",
    "attack_id": "T1557.002",
    "action": "quarantine",
    "reason": "10.20.0.1 başka MAC tarafından sahipleniliyor",
    "extra_ignored": 123,
}


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


def test_build_payload_contains_exact_fields():
    data = json.loads(build_payload(SAMPLE_ALERT))
    assert set(data.keys()) == {"type", "mac", "ip", "severity", "attack_id", "action", "reason"}
    assert data["type"] == "arp_spoofing"
    assert data["attack_id"] == "T1557.002"


def test_syslog_disabled_when_wazuh_ip_is_missing(tmp_path):
    fwd = SyslogForwarder({"network": {"wazuh_ip": None}})
    assert not fwd.enabled
    assert fwd.send(SAMPLE_ALERT) is False
    conn = db.connect(str(tmp_path / "t.db"))
    fwd.on_alert(conn, 999)   # hata vermemeli


def test_syslog_format_matches_wazuh_decoder_expectation():
    cap = _CaptureHandler()
    fwd = SyslogForwarder({"network": {"wazuh_ip": "127.0.0.1"}}, handler=cap)
    assert fwd.send(SAMPLE_ALERT) is True
    [line] = cap.lines
    # Örn: "Nov 25 22:50:01 rogueguard-lab rogueguard: {...}"
    m = re.match(r"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} rogueguard-lab rogueguard: (\{.*\})$",
                 line)
    assert m, f"beklenmeyen syslog formatı: {line!r}"
    assert json.loads(m.group(1))["type"] == "arp_spoofing"


def test_syslog_sends_udp_datagram_from_db_alert(tmp_path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)
    port = sock.getsockname()[1]
    try:
        conn = db.connect(str(tmp_path / "t.db"))
        cur = conn.execute(
            "INSERT INTO alerts (ts, mac, ip, type, severity, attack_id, action, reason, "
            "detected_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 1)",
            (SAMPLE_ALERT["mac"], SAMPLE_ALERT["ip"], SAMPLE_ALERT["type"],
             SAMPLE_ALERT["severity"], SAMPLE_ALERT["attack_id"], SAMPLE_ALERT["action"],
             SAMPLE_ALERT["reason"]),
        )
        fwd = SyslogForwarder({"network": {"wazuh_ip": "127.0.0.1"}}, port=port)
        fwd.on_alert(conn, cur.lastrowid)
        fwd.close()
        raw, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    text = raw.decode("utf-8").rstrip("\x00")
    assert "rogueguard-lab rogueguard: " in text
    payload = json.loads(text.split("rogueguard-lab rogueguard: ", 1)[1])
    assert payload["mac"] == SAMPLE_ALERT["mac"]
    assert payload["attack_id"] == "T1557.002"


def test_syslog_swallows_socket_error_when_target_unreachable():
    class _BrokenHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            raise OSError("network unreachable")

    fwd = SyslogForwarder({"network": {"wazuh_ip": "10.160.244.99"}}, handler=_BrokenHandler())
    assert fwd.send(SAMPLE_ALERT) is False
