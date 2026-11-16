"""6.4 testleri: container seçimi (MAC taklidinde doğru olanı), br-quar'a taşıma komutu ve
alarm aksiyonunun uygulanması. incus ve nft çağrıları sahte çalıştırıcıyla değiştirilir."""
import json

from rogueguard import db
from rogueguard.containment.actions import Containment
from rogueguard.containment.quarantine import Quarantine, pick_container
from rogueguard.learn import save_device

MAC = "00:40:8c:3a:51:b2"
CFG = {"network": {"iot_iface": "br-iot"}, "containment": {"quarantine_bridge": "br-quar"}}
DEVICE = {"mac": MAC, "oui": "00:40:8c", "ip": "10.20.0.111", "hostname": "cam", "opt55": [1],
          "vendor_class": "v", "mdns": [], "destinations": [], "interval": None}


def container(name, mac, ip=None, created="2026-11-15T00:00:00Z", parent="br-iot",
              status="Running", volatile=False):
    eth0 = {"nictype": "bridged", "parent": parent, "type": "nic"}
    config = {"volatile.eth0.hwaddr": mac} if volatile else {}
    if not volatile:
        eth0["hwaddr"] = mac
    addrs = [{"family": "inet", "address": ip}] if ip else []
    return {"name": name, "status": status, "created_at": created, "config": config,
            "expanded_devices": {"eth0": eth0},
            "state": {"network": {"eth0": {"addresses": addrs}}}}


class FakeRouter:
    approved_set, block_set = "rg_approved", "rg_block"

    def __init__(self, approved=()):
        self.sets = {"rg_approved": set(approved), "rg_block": set()}

    def add(self, name, ip): self.sets[name].add(ip)
    def remove(self, name, ip): self.sets[name].remove(ip)
    def members(self, name): return set(self.sets[name])


def test_pick_container_finds_single_match_including_auto_mac():
    cs = [container("cam-01", MAC, "10.20.0.111"),
          container("rogue", "10:66:6a:00:00:01", "10.20.0.130", volatile=True)]
    assert pick_container(cs, "10:66:6A:00:00:01", "br-iot", None) == "rogue"
    assert pick_container(cs, "aa:aa:aa:aa:aa:aa", "br-iot", None) is None


def test_pick_container_with_cloned_mac_chooses_the_one_not_matching_inventory():
    victim = container("cam-01", MAC, "10.20.0.111", created="2026-11-15T00:00:00Z")
    rogue_no_ip = container("rogue", MAC, None, created="2026-11-16T00:00:00Z")
    assert pick_container([victim, rogue_no_ip], MAC, "br-iot", "10.20.0.111") == "rogue"
    rogue_same_ip = container("rogue", MAC, "10.20.0.111", created="2026-11-16T00:00:00Z")
    assert pick_container([rogue_same_ip, victim], MAC, "br-iot", "10.20.0.111") == "rogue"


def test_pick_container_sees_mac_changed_inside_the_container():
    rogue = container("rogue", "10:66:6a:00:00:01", volatile=True, created="2026-11-16T00:00:00Z")
    rogue["state"]["network"]["eth0"]["hwaddr"] = MAC          # içeriden değiştirilmiş MAC
    victim = container("cam-01", MAC, "10.20.0.111")
    assert pick_container([victim, rogue], MAC, "br-iot", "10.20.0.111") == "rogue"


def test_pick_container_ignores_stopped_and_already_quarantined():
    cs = [container("a", MAC, status="Stopped"), container("b", MAC, parent="br-quar")]
    assert pick_container(cs, MAC, "br-iot", None) is None


def test_isolate_moves_eth0_to_quarantine_bridge():
    calls = []

    def runner(cmd):
        calls.append(cmd)
        return json.dumps([container("rogue", MAC)]) if cmd[1] == "list" else ""
    assert Quarantine(CFG, runner).isolate(MAC, None) == "rogue"
    assert calls[-1] == ["incus", "config", "device", "set", "rogue", "eth0", "parent=br-quar"]


def setup(tmp_path, atype, action, mac=MAC, ip="10.20.0.111"):
    conn = db.connect(str(tmp_path / "t.db"))
    save_device(conn, DEVICE, "device", [], 0.0)
    cur = conn.execute("INSERT INTO alerts (ts, mac, ip, type, severity, action, detected_at) "
                       "VALUES (1, ?, ?, ?, 'high', ?, 1)", (mac, ip, atype, action))
    return conn, cur.lastrowid


class FakeQuarantine:
    def __init__(self, name): self.name, self.calls = name, []

    def isolate(self, mac, inventory_ip):
        self.calls.append((mac, inventory_ip))
        return self.name


def status(conn):
    return conn.execute("SELECT status FROM devices WHERE mac=?", (MAC,)).fetchone()[0]


def contained(conn, alert_id):
    return conn.execute("SELECT contained_at FROM alerts WHERE id=?", (alert_id,)).fetchone()[0]


def test_impersonation_quarantines_container_but_leaves_victim_approved(tmp_path):
    conn, aid = setup(tmp_path, "impersonation", "quarantine", ip=None)
    router, quar = FakeRouter({"10.20.0.111"}), FakeQuarantine("rogue")
    Containment(router, quar, clock=lambda: 5.0).apply(conn, aid)
    assert quar.calls == [(MAC, "10.20.0.111")]
    assert status(conn) == "approved" and router.sets["rg_approved"] == {"10.20.0.111"}
    assert contained(conn, aid) == 5.0


def test_arp_spoofing_quarantines_and_revokes_approval(tmp_path):
    conn, aid = setup(tmp_path, "arp_spoofing", "quarantine")
    router = FakeRouter({"10.20.0.111"})
    Containment(router, FakeQuarantine("cam-01"), clock=lambda: 5.0).apply(conn, aid)
    assert status(conn) == "quarantined" and router.sets["rg_approved"] == set()


def test_block_adds_ip_to_block_set_and_marks_device(tmp_path):
    conn, aid = setup(tmp_path, "abnormal_scan", "block")
    router = FakeRouter({"10.20.0.111"})
    Containment(router, FakeQuarantine(None), clock=lambda: 7.0).apply(conn, aid)
    assert router.sets == {"rg_approved": set(), "rg_block": {"10.20.0.111"}}
    assert status(conn) == "blocked" and contained(conn, aid) == 7.0


def test_pending_action_and_missing_container_do_not_mark_contained(tmp_path):
    conn, aid = setup(tmp_path, "unknown_device", "pending")
    Containment(FakeRouter(), FakeQuarantine(None)).apply(conn, aid)
    assert contained(conn, aid) is None
    conn2, aid2 = setup(tmp_path / "x", "impersonation", "quarantine")
    Containment(FakeRouter(), FakeQuarantine(None)).apply(conn2, aid2)
    assert contained(conn2, aid2) is None
