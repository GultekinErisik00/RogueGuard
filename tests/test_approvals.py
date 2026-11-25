"""6.6 testleri: dashboard veri katmanı (approvals yazma + cihaz/alarm okuma) ve
daemon onay akışı (approve → rg_approved + parmak izi doldurma, reject → rg_block)."""
import json
import pytest

from dashboard import data as dash_data
from rogueguard import db
from rogueguard.containment.approvals import apply_pending
from tests.test_containment import FakeRouter

NEW_MAC = "02:00:00:11:22:33"


def _seed_pending(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    conn.execute(
        "INSERT INTO devices (mac, ip, hostname, vendor, status, first_seen, last_seen) "
        "VALUES (?, '10.20.0.155', NULL, '02:00:00', 'pending', 100.0, 100.0)",
        (NEW_MAC,),
    )
    db.add_observation(conn, NEW_MAC, "10.20.0.155", "dhcp", {
        "msg_type": "request",
        "hostname": "new-sensor-01",
        "vendor_class": "NewSensor",
        "param_req_list": [1, 3, 6],
    })
    db.add_observation(conn, NEW_MAC, "10.20.0.155", "mdns", {
        "services": ["_http._tcp"], "hostname": "new-sensor-01",
    })
    return conn


def test_approve_updates_status_populates_fingerprint_and_adds_to_router(tmp_path):
    conn = _seed_pending(tmp_path)
    router = FakeRouter()
    router.sets["rg_block"].add("10.20.0.155")

    dash_data.submit_approval(conn, NEW_MAC, "approve", ts=200.0)
    assert dash_data.load_pending(conn)[0]["queued_decision"] == "approve"

    count = apply_pending(conn, router, clock=lambda: 205.0)
    assert count == 1
    assert apply_pending(conn, router, clock=lambda: 210.0) == 0   # tekrar uygulanmaz

    dev = conn.execute("SELECT * FROM devices WHERE mac=?", (NEW_MAC,)).fetchone()
    assert dev["status"] == "approved"
    assert dev["hostname"] == "new-sensor-01"
    assert json.loads(dev["dhcp_fp"]) == {"opt55": [1, 3, 6], "vendor_class": "NewSensor"}
    assert json.loads(dev["mdns"]) == ["_http._tcp"]
    assert router.sets == {"rg_approved": {"10.20.0.155"}, "rg_block": set()}

    app = conn.execute("SELECT applied_at FROM approvals").fetchone()
    assert app["applied_at"] == 205.0


def test_reject_blocks_device_and_moves_ip_out_of_approved(tmp_path):
    conn = _seed_pending(tmp_path)
    router = FakeRouter({"10.20.0.155"})

    dash_data.submit_approval(conn, NEW_MAC, "reject", ts=200.0)
    assert apply_pending(conn, router, clock=lambda: 202.0) == 1

    status = conn.execute("SELECT status FROM devices WHERE mac=?", (NEW_MAC,)).fetchone()["status"]
    assert status == "blocked"
    assert router.sets == {"rg_approved": set(), "rg_block": {"10.20.0.155"}}


def test_invalid_decision_and_missing_device_are_handled_cleanly(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    with pytest.raises(ValueError):
        dash_data.submit_approval(conn, NEW_MAC, "maybe")

    conn.execute("INSERT INTO approvals (ts, mac, decision) VALUES (1, ?, 'approve')", (NEW_MAC,))
    assert apply_pending(conn, FakeRouter(), clock=lambda: 5.0) == 0
    assert conn.execute("SELECT applied_at FROM approvals").fetchone()["applied_at"] == 5.0


def test_dashboard_loaders_return_devices_and_alerts_with_ttc(tmp_path):
    conn = _seed_pending(tmp_path)
    conn.execute(
        "INSERT INTO alerts (ts, mac, ip, type, severity, attack_id, action, reason, "
        "detected_at, contained_at) VALUES (300, ?, '10.20.0.155', 'unknown_device', "
        "'medium', 'T1200', 'pending', 'test', 300.0, 300.45)",
        (NEW_MAC,),
    )
    devs = dash_data.load_devices(conn)
    assert len(devs) == 1 and devs[0]["mac"] == NEW_MAC
    als = dash_data.load_alerts(conn)
    assert len(als) == 1 and als[0]["ttc_s"] == 0.45 and als[0]["attack_id"] == "T1200"
