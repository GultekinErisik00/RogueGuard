"""Keşif modülünün saf (ağ gerektirmeyen) parçaları için birim testleri."""
from rogueguard import db
from rogueguard.discovery.arp_scan import ArpDedup
from rogueguard.discovery.events import EventTracker
from rogueguard.fingerprint import dhcp, mdns
from rogueguard.fingerprint.traffic import TrafficWindow


def test_dhcp_parse_options_extracts_fingerprint_fields():
    options = [("message-type", 3), ("client_id", b"\x01\x00\x40\x8c\x3a\x51\xb2"),
               ("hostname", b"axis-m3045-51b2"), ("vendor_class_id", b"AXIS,Network Camera"),
               ("param_req_list", [1, 3, 6, 12, 15, 28, 42]), ("requested_addr", "10.20.0.111"),
               "end", "pad"]
    parsed = dhcp.parse_options(options)
    assert parsed["msg_type"] == "request"
    assert parsed["hostname"] == "axis-m3045-51b2"
    assert parsed["vendor_class"] == "AXIS,Network Camera"
    assert parsed["param_req_list"] == [1, 3, 6, 12, 15, 28, 42]
    assert parsed["client_id"] == "0100408c3a51b2"
    assert dhcp.fingerprint(parsed) == {k: parsed[k] for k in
                                        ("hostname", "vendor_class", "param_req_list", "client_id")}


def test_mdns_parse_records_ignores_dns_sd_meta_type():
    records = [(12, b"_services._dns-sd._udp.local.", b"_http._tcp.local."),
               (12, b"_http._tcp.local.", b"axis-m3045-51b2._http._tcp.local."),
               (12, b"_rtsp._tcp.local.", b"axis-m3045-51b2._rtsp._tcp.local."),
               (1, b"axis-m3045-51b2.local.", "10.20.0.111")]
    parsed = mdns.parse_records(records)
    assert parsed["services"] == ["_http._tcp", "_rtsp._tcp"]
    assert parsed["hostname"] == "axis-m3045-51b2"


def test_event_tracker_new_then_changed_ip():
    tr = EventTracker(known=set())
    assert [e for e, _ in tr.update("aa", "10.0.0.5", "arp", {})] == ["new_device"]
    assert tr.update("aa", "10.0.0.5", "arp", {}) == []
    events = tr.update("aa", "10.0.0.9", "arp", {})
    assert events == [("changed_device", {"ip": {"old": "10.0.0.5", "new": "10.0.0.9"}})]


def test_event_tracker_known_mac_is_not_new_and_dhcp_change_detected():
    tr = EventTracker(known={"aa"})
    req = {"msg_type": "request", "hostname": "x", "param_req_list": [1, 3]}
    assert tr.update("aa", None, "dhcp", req) == []
    events = tr.update("aa", None, "dhcp", dict(req, param_req_list=[1, 3, 6]))
    assert events[0][0] == "changed_device" and "dhcp_fp" in events[0][1]


def test_event_tracker_ignores_release_and_routed_traffic_ip():
    tr = EventTracker(known={"aa", "router"})
    tr.update("aa", None, "dhcp", {"msg_type": "request", "hostname": "x", "client_id": "01"})
    assert tr.update("aa", None, "dhcp", {"msg_type": "release", "client_id": "01"}) == []
    tr.update("router", "10.20.0.1", "arp", {})
    assert tr.update("router", "10.20.2.10", "traffic", {}) == []


def test_arp_dedup_limits_repeats():
    d = ArpDedup(every=300)
    assert d.should_record("aa", "1.1.1.1", now=0)
    assert not d.should_record("aa", "1.1.1.1", now=100)
    assert d.should_record("aa", "1.1.1.2", now=100)   # yeni çift hemen
    assert d.should_record("aa", "1.1.1.1", now=301)


def test_traffic_window_publish_interval():
    w = TrafficWindow()
    for t in (0, 10, 20, 30):
        w.add(t, "aa", "10.20.0.5", "10.20.2.10", 1883, "tcp", 40)
    w.add(31, "aa", "10.20.0.5", "10.20.0.1", 53, "udp", 30)
    [(mac, ip, data)] = w.flush()
    assert data["publishes"] == 4 and data["publish_interval_median"] == 10
    assert data["destinations"] == ["10.20.0.1:53/udp", "10.20.2.10:1883/tcp"]
    assert w.flush() == []


def test_db_roundtrip(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    db.add_observation(conn, "aa", "1.2.3.4", "arp", {"x": 1})
    assert db.known_macs(conn) == {"aa"}
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
