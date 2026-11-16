"""`full` profilin ek tespitleri: ARP zehirleme, tarama ve davranış sapması (ağ gerektirmez)."""
from rogueguard.decision.arp_guard import spoof_reason
from rogueguard.decision.behavior import BehaviorMonitor
from rogueguard.decision.scan import ScanDetector
from tests.test_decision import CAM, ROGUE_MAC, alerts, make_engine

GW_IP, BROKER = "10.20.0.1", "10.20.2.10:1883/tcp"
INVENTORY = {"destinations": [BROKER], "interval": 10.0}


def test_spoof_reason_only_when_another_mac_claims_a_bound_ip():
    assert spoof_reason("aa:aa:aa:aa:aa:aa", GW_IP, "10:66:6a:01:0d:3f")
    assert spoof_reason("10:66:6A:01:0D:3F", GW_IP, "10:66:6a:01:0d:3f") is None
    assert spoof_reason("aa:aa:aa:aa:aa:aa", "10.20.0.50", None) is None      # sahipsiz IP
    assert spoof_reason("aa:aa:aa:aa:aa:aa", "0.0.0.0", "10:66:6a:01:0d:3f") is None  # ARP probe


def test_scan_detector_counts_distinct_targets_inside_window():
    scan = ScanDetector(window=30, arp_targets=3, syn_targets=5)
    assert scan.add("arp", 0, "aa", "10.20.0.1") is None
    assert scan.add("arp", 1, "aa", "10.20.0.1") is None          # aynı hedef sayılmaz
    assert scan.add("arp", 2, "aa", "10.20.0.2") is None
    assert "3 farklı hedef" in scan.add("arp", 3, "aa", "10.20.0.3")
    assert scan.add("arp", 100, "bb", "10.20.0.1") is None
    assert scan.add("arp", 200, "bb", "10.20.0.2") is None        # pencere dışı
    assert scan.add("arp", 201, "bb", "10.20.0.3") is None


def test_behavior_needs_k_consecutive_deviating_windows():
    mon = BehaviorMonitor(windows=3, window_seconds=60, rate_factor=3, rate_slack=5,
                          ignore_ips={"10.20.0.1", "10.20.0.2"})
    bad = {"destinations": [BROKER, "8.8.8.8:443/tcp"], "publishes": 6}
    ok = {"destinations": [BROKER, "10.20.0.1:53/udp"], "publishes": 6}
    assert mon.check("aa", INVENTORY, bad) is None
    assert mon.check("aa", INVENTORY, bad) is None
    assert mon.check("aa", INVENTORY, ok) is None                  # temiz pencere sayacı sıfırlar
    assert mon.check("aa", INVENTORY, bad) is None
    assert mon.check("aa", INVENTORY, bad) is None
    assert "8.8.8.8:443/tcp" in mon.check("aa", INVENTORY, bad)


def test_behavior_flags_publish_flood_but_not_silence():
    mon = BehaviorMonitor(1, 60, 3, 5, set())
    assert mon.check("aa", INVENTORY, {"destinations": [BROKER], "publishes": 0}) is None
    assert mon.check("aa", INVENTORY, {"destinations": [BROKER], "publishes": 23}) is None
    assert "yayın sayısı 24" in mon.check("aa", INVENTORY, {"destinations": [BROKER],
                                                            "publishes": 24})


def test_engine_full_profile_raises_arp_spoofing_against_the_sender(tmp_path):
    engine, conn, _ = make_engine(tmp_path, profile="full")
    engine.on_arp(1.0, ROGUE_MAC, ROGUE_MAC, CAM["ip"], "10.20.0.1")
    [alert] = alerts(conn)
    assert (alert["type"], alert["mac"], alert["attack_id"], alert["action"]) == \
           ("arp_spoofing", ROGUE_MAC, "T1557.002", "quarantine")
    engine.on_arp(2.0, CAM["mac"], CAM["mac"], CAM["ip"], "10.20.0.1")   # gerçek sahibi: sessiz
    assert len(alerts(conn)) == 1


def test_engine_full_profile_raises_scan_and_other_profiles_ignore_port_tap(tmp_path):
    engine, conn, _ = make_engine(tmp_path, profile="full")
    for i in range(15):
        engine.on_syn(float(i), ROGUE_MAC, "10.20.0.150", "10.20.0.111", 1000 + i)
    [alert] = alerts(conn)
    assert (alert["type"], alert["attack_id"], alert["action"], alert["ip"]) == \
           ("abnormal_scan", "T1046", "block", "10.20.0.150")

    quiet, conn2, _ = make_engine(tmp_path / "fp", profile="fingerprint")
    quiet.on_arp(1.0, ROGUE_MAC, ROGUE_MAC, CAM["ip"], "10.20.0.1")
    for i in range(15):
        quiet.on_syn(float(i), ROGUE_MAC, "10.20.0.150", "10.20.0.111", 1000 + i)
    assert alerts(conn2) == []


def test_engine_full_profile_raises_abnormal_behavior_after_k_windows(tmp_path):
    engine, conn, _ = make_engine(tmp_path, profile="full")
    bad = {"destinations": ["8.8.8.8:443/tcp"], "publishes": 0}
    for _ in range(2):
        engine.on_observation(CAM["mac"], CAM["ip"], "traffic", bad)
    assert alerts(conn) == []
    engine.on_observation(CAM["mac"], CAM["ip"], "traffic", bad)
    assert [(a["type"], a["action"]) for a in alerts(conn)] == [("abnormal_behavior", "block")]


def test_reassigned_ip_clears_previous_owner_binding(tmp_path):
    engine, conn, _ = make_engine(tmp_path, profile="full")
    conn.execute("INSERT INTO devices (mac, ip, status) VALUES ('bb:bb:bb:00:00:02', "
                 "'10.20.0.120', 'approved')")
    engine.on_observation(CAM["mac"], "10.20.0.120", "dhcp", {"msg_type": "ack"})
    engine.on_arp(1.0, CAM["mac"], CAM["mac"], "10.20.0.120", "10.20.0.1")
    assert alerts(conn) == []
