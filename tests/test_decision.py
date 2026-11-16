"""Karar motoru (6.3) birim testleri: ağ gerektirmez, geçici SQLite ve sahte saat kullanır."""
import pytest

from rogueguard import db
from rogueguard.decision.attack_map import ATTACKS
from rogueguard.decision.engine import DecisionEngine
from rogueguard.learn import save_device

CAM = {"mac": "00:40:8c:3a:51:b2", "oui": "00:40:8c", "ip": "10.20.0.111",
       "hostname": "axis-m3045-51b2", "opt55": [1, 3, 6, 12, 15, 28, 42],
       "vendor_class": "udhcp 1.36.1", "mdns": ["_http._tcp"], "destinations": [],
       "interval": 40.0}
REQUEST = {"msg_type": "request", "hostname": "axis-m3045-51b2",
           "vendor_class": "udhcp 1.36.1", "param_req_list": [1, 3, 6, 12, 15, 28, 42]}
ROGUE_MAC = "02:00:00:aa:bb:cc"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_engine(tmp_path, profile="fingerprint"):
    cfg = {"network": {"sensor_iot_ip": "10.20.0.2"},
           "decision": {"detection_profile": profile, "match_min": 0.9, "alert_cooldown": 300}}
    conn = db.connect(str(tmp_path / "t.db"))
    save_device(conn, CAM, "device", [{"port": 80, "proto": "tcp"}], 0.0)
    clock = Clock()
    return DecisionEngine(cfg, conn=conn, clock=clock), conn, clock


def alerts(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id")]


def test_unknown_mac_raises_unknown_device_and_goes_pending(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    engine.on_observation(ROGUE_MAC, "10.20.0.150", "arp", {})
    engine.on_observation(ROGUE_MAC, "10.20.0.150", "arp", {})   # ikinci kez alarm üretmez
    [alert] = alerts(conn)
    assert (alert["type"], alert["attack_id"], alert["severity"], alert["action"]) == \
           ("unknown_device", "T1200", "medium", "pending")
    row = conn.execute("SELECT status FROM devices WHERE mac=?", (ROGUE_MAC,)).fetchone()
    assert row["status"] == "pending"


def test_known_device_with_same_dhcp_fingerprint_is_quiet(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    engine.on_observation(CAM["mac"], "10.20.0.111", "dhcp", REQUEST)
    assert alerts(conn) == []


def test_cloned_mac_with_different_dhcp_fingerprint_is_impersonation(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    clone = dict(REQUEST, vendor_class="dhcpcd-10.0.6", param_req_list=[1, 28, 2, 3, 15, 6])
    engine.on_observation(CAM["mac"], "10.20.0.150", "dhcp", clone)
    [alert] = alerts(conn)
    assert (alert["type"], alert["attack_id"], alert["severity"], alert["action"]) == \
           ("impersonation", "T1036", "high", "quarantine")
    assert "opt55" in alert["reason"] and "vendor_class" in alert["reason"]


def test_impersonation_is_rate_limited_by_cooldown(tmp_path):
    engine, conn, clock = make_engine(tmp_path)
    clone = dict(REQUEST, hostname="evil")
    engine.on_observation(CAM["mac"], "10.20.0.150", "dhcp", clone)
    clock.now += 60
    engine.on_observation(CAM["mac"], "10.20.0.150", "dhcp", clone)
    assert len(alerts(conn)) == 1
    clock.now += 300
    engine.on_observation(CAM["mac"], "10.20.0.150", "dhcp", clone)
    assert len(alerts(conn)) == 2


def test_dhcp_ack_with_new_ip_updates_device_without_alert(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    engine.on_observation(CAM["mac"], "10.20.0.177", "dhcp", {"msg_type": "ack"})
    assert alerts(conn) == []
    ip = conn.execute("SELECT ip FROM devices WHERE mac=?", (CAM["mac"],)).fetchone()["ip"]
    assert ip == "10.20.0.177"


def test_ip_change_hook_moves_approved_ip_but_not_after_impersonation(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    moves = []
    engine._on_ip_change = lambda mac, old, new: moves.append((old, new))
    engine.on_observation(CAM["mac"], "10.20.0.112", "dhcp", {"msg_type": "ack"})
    assert moves == [("10.20.0.111", "10.20.0.112")]
    engine.on_observation(CAM["mac"], None, "dhcp", dict(REQUEST, hostname="fedora"))
    engine.on_observation(CAM["mac"], "10.20.0.150", "dhcp", {"msg_type": "ack"})
    assert len(moves) == 1                       # taklitçinin IP'si onaylı sete taşınmaz
    assert conn.execute("SELECT ip FROM devices WHERE mac=?", (CAM["mac"],)).fetchone()[0] \
        == "10.20.0.112"


def test_pending_device_ip_is_filled_in_later(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    engine.on_observation(ROGUE_MAC, None, "dhcp", {"msg_type": "discover", "hostname": "r1"})
    engine.on_observation(ROGUE_MAC, "10.20.0.130", "arp", {})
    row = conn.execute("SELECT ip, status FROM devices WHERE mac=?", (ROGUE_MAC,)).fetchone()
    assert tuple(row) == ("10.20.0.130", "pending")
    assert len(alerts(conn)) == 1
    engine.on_observation(ROGUE_MAC, CAM["ip"], "arp", {})        # sahte ARP: onaylı IP'yi alamaz
    assert conn.execute("SELECT ip FROM devices WHERE mac=?", (ROGUE_MAC,)).fetchone()[0] \
        == "10.20.0.130"


def test_allowlist_profile_only_checks_mac(tmp_path):
    engine, conn, _ = make_engine(tmp_path, profile="allowlist")
    engine.on_observation(CAM["mac"], "10.20.0.150", "dhcp", dict(REQUEST, hostname="evil"))
    assert alerts(conn) == []
    engine.on_observation(ROGUE_MAC, "10.20.0.151", "arp", {})
    assert [a["type"] for a in alerts(conn)] == ["unknown_device"]


def test_sensor_own_address_is_ignored(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    engine.on_observation("02:00:00:00:00:02", "10.20.0.2", "arp", {})
    assert alerts(conn) == []


def test_sweep_flags_macs_seen_before_protect_started(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    db.add_observation(conn, ROGUE_MAC, "10.20.0.160", "arp", {})
    db.add_observation(conn, CAM["mac"], "10.20.0.111", "arp", {})
    engine.sweep()
    assert [(a["type"], a["mac"]) for a in alerts(conn)] == [("unknown_device", ROGUE_MAC)]


def test_unknown_detection_profile_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        make_engine(tmp_path, profile="paranoid")


def test_attack_map_matches_claude_md_table():
    assert ATTACKS["unknown_device"].attack_id == "T1200"
    assert ATTACKS["impersonation"].action == "quarantine"
    assert ATTACKS["arp_spoofing"].attack_id == "T1557.002"
    assert ATTACKS["abnormal_scan"].action == "block"
    assert ATTACKS["abnormal_behavior"].attack_id is None


def test_alert_hook_receives_new_alert_id(tmp_path):
    engine, conn, _ = make_engine(tmp_path)
    seen = []
    engine._on_alert = lambda c, alert_id: seen.append(alert_id)
    engine.on_observation(ROGUE_MAC, "10.20.0.150", "arp", {})
    assert seen == [alerts(conn)[0]["id"]]
