"""6.2 testleri: nmap XML ayrıştırma, router set komutları, öğrenme kaydı ve —hocanın
1. geri bildirimi için— meşru cihazların ikili parmak izi benzerliği."""
import itertools
import time
from pathlib import Path

import pytest
import yaml

from rogueguard import config, db, learn
from rogueguard.containment.router import Router
from rogueguard.fingerprint import compare, ports, profile

ROOT = config.ROOT
CFG = config.load()
ESIK = CFG["fingerprint"]["similarity_max"]
WEIGHTS = CFG["fingerprint"]["weights"]
TWINS = {frozenset({"cam-01", "cam-02"})}     # bilinçli ikiz: beklenen tek istisna

NMAP_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Boa" version="0.94"/></port>
<port protocol="tcp" portid="81"><state state="closed"/><service name="x"/></port>
<port protocol="tcp" portid="554"><state state="open"/><service name="rtsp"/></port>
</ports></host></nmaprun>"""


def test_nmap_xml_parses_only_open_ports():
    rows = ports.parse_nmap_xml(NMAP_XML)
    assert [(r["port"], r["service"], r["banner"]) for r in rows] == \
        [(80, "http", "Boa 0.94"), (554, "rtsp", "")]


def test_nmap_scan_refuses_outside_lab_subnet():
    with pytest.raises(ValueError):
        ports.scan("8.8.8.8", "10.20.0.0/24")


def test_router_sync_flushes_then_adds_and_rejects_bad_ip():
    calls = []
    r = Router(CFG, runner=lambda cmd: calls.append(cmd) or "")
    r.sync(["10.20.0.111"], ["10.20.0.150"])
    assert calls[0][-4:] == ["flush", "set", "inet", "rg"] or "flush" in calls[0]
    assert ["incus", "exec", "rg-router", "--", "nft", "add", "element", "inet", "rg",
            "rg_approved", "{ 10.20.0.111 }"] in calls
    assert any(c[-2:] == ["rg_block", "{ 10.20.0.150 }"] for c in calls)
    with pytest.raises(ValueError):
        r.add("rg_approved", "1.1.1.1; reboot")


def test_learn_saves_approved_device_and_marks_router_infrastructure(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    t0 = time.time() - 1
    db.add_observation(conn, "aa:aa:aa:00:00:01", "10.20.0.1", "arp", {})
    db.add_observation(conn, "bb:bb:bb:00:00:02", "10.20.0.111", "arp", {})
    db.add_observation(conn, "bb:bb:bb:00:00:02", None, "dhcp",
                       {"msg_type": "request", "hostname": "h", "vendor_class": "v",
                        "param_req_list": [1, 3]})
    kinds = learn.learned_macs(conn, t0, "10.20.0.1")
    assert kinds == {"aa:aa:aa:00:00:01": "infrastructure", "bb:bb:bb:00:00:02": "device"}
    prof = profile.build_from_observations(conn, "bb:bb:bb:00:00:02")
    assert (prof["ip"], prof["hostname"], prof["opt55"]) == ("10.20.0.111", "h", [1, 3])
    learn.save_device(conn, prof, "device", [], time.time())
    row = conn.execute("SELECT status, ip FROM devices").fetchone()
    assert (row["status"], row["ip"]) == ("approved", "10.20.0.111")


def _pairs(profiles: dict):
    return itertools.combinations(sorted(profiles), 2)


def _check_pairwise(profiles: dict) -> None:
    for a, b in _pairs(profiles):
        score = compare.similarity(profiles[a], profiles[b], WEIGHTS)
        if frozenset({a, b}) in TWINS:
            assert score > ESIK, f"{a}/{b} ikiz olduğu için benzer çıkmalı ({score:.2f})"
        else:
            assert score < ESIK, f"{a} ile {b} çok benzer: {score:.2f} >= {ESIK}"


def test_lab_profiles_are_pairwise_distinct_except_camera_twins():
    spec = yaml.safe_load((ROOT / "lab/devices.yaml").read_text())["devices"]
    _check_pairwise({n: profile.build_from_spec(n, s) for n, s in spec.items()})


def test_learned_inventory_is_pairwise_distinct_except_camera_twins():
    inv = ROOT / CFG["learn"]["inventory_path"]
    if not inv.exists():
        pytest.skip("inventory.yaml yok: önce `learn` çalıştırılmalı")
    names = {s["mac"].lower(): n for n, s in yaml.safe_load(
        (ROOT / "lab/devices.yaml").read_text())["devices"].items()}
    learned = {names[p["mac"]]: p for p in yaml.safe_load(inv.read_text())["devices"]
               if p["mac"] in names}
    assert len(learned) == len(names), "envanterde 6 meşru cihaz olmalı"
    _check_pairwise(learned)
