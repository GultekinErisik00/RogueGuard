"""7B testleri (lab erişimi olmadan): koşu sonucu hesabı (TTD/TTC, yanlış pozitif, t0 öncesi
gürültü, arpwatch MAC biçimi), metrik özeti, baseline/run DB hazırlığı, kaldığı yerden devam
ve protect için config geçersiz kılma."""
from experiments import metrics, run_scenarios as rs
from experiments.outcome import Expectation, arpwatch_hits, evaluate, norm_mac
from rogueguard import config, db

ROGUE = "10:66:6a:aa:bb:cc"
VICTIM = "00:40:8c:3a:51:b2"


def test_evaluate_measures_ttd_ttc_and_ignores_pre_t0_noise():
    alerts = [{"ts": 95.0, "mac": "00:11:50:5f:2a:c3", "type": "unknown_device", "contained_at": None},
              {"ts": 100.4, "mac": ROGUE, "type": "unknown_device", "contained_at": None}]
    row = evaluate(Expectation(ROGUE, frozenset({"unknown_device"})), 100.0, alerts, [])
    assert row["detected"] and row["type_correct"]
    assert row["ttd_s"] == 0.4 and row["ttc_s"] is None
    assert row["pre_alerts"] == 1 and row["fp_alerts"] == 0


def test_evaluate_type_correct_uses_first_alert_and_counts_other_macs_as_fp():
    alerts = [{"ts": 101.0, "mac": VICTIM, "type": "abnormal_scan", "contained_at": 101.5},
              {"ts": 102.0, "mac": VICTIM, "type": "impersonation", "contained_at": 102.2},
              {"ts": 103.0, "mac": "00:1b:a9:6c:20:8f", "type": "arp_spoofing", "contained_at": None}]
    row = evaluate(Expectation(VICTIM, frozenset({"impersonation"})), 100.0, alerts, [])
    assert row["detected"] and not row["type_correct"]
    assert row["first_type"] == "abnormal_scan"
    assert row["alert_types"] == "abnormal_scan;impersonation"
    assert row["ttd_s"] == 2.0 and row["ttc_s"] == 1.5
    assert row["fp_alerts"] == 1 and row["fp_types"] == "arp_spoofing"


def test_benign_scenario_counts_every_alert_as_false_positive():
    alerts = [{"ts": 110.0, "mac": VICTIM, "type": "impersonation", "contained_at": 110.3}]
    row = evaluate(Expectation(None), 100.0, alerts, [])
    assert not row["detected"] and row["fp_alerts"] == 1


def test_arpwatch_mac_without_leading_zeros_is_matched():
    assert norm_mac("0:40:8c:3a:51:b2") == VICTIM
    lines = [(101.0, "arpwatch[9]: new station 10.20.0.153 10:66:6a:aa:bb:cc br-iot"),
             (102.0, "arpwatch[9]: listening on br-iot"),
             (103.0, "arpwatch[9]: flip flop 10.20.0.112 0:40:8c:3a:51:b2 (10:66:6a:aa:bb:cc)")]
    assert arpwatch_hits(lines, ROGUE) == [(101.0, "new station"), (103.0, "flip flop")]
    assert arpwatch_hits(lines, VICTIM) == [(103.0, "flip flop")]
    row = evaluate(Expectation(ROGUE, frozenset({"unknown_device"})), 100.0, [], lines)
    assert row["arpwatch_detected"] and row["arpwatch_ttd_s"] == 1.0


def _row(**kw):
    base = {c: "" for c in rs.COLUMNS}
    base |= {"profile": "full", "scenario": "R1", "rep": "0", "detected": "True",
             "type_correct": "True", "fp_alerts": "0", "arpwatch_detected": "False"}
    return base | {k: str(v) for k, v in kw.items()}


def test_metrics_summarize_and_render():
    rows = [_row(ttd_s=0.4, ttc_s=0.6), _row(rep=1, ttd_s=0.6),
            _row(rep=2, detected="False", type_correct="False", arpwatch_detected="True",
                 arpwatch_ttd_s=8.0),
            _row(scenario="B1", detected="False", type_correct="False", fp_alerts=2)]
    s = metrics.summarize(rows)
    r1 = s[("full", "R1")]
    assert r1["n"] == 3 and round(r1["detect_rate"], 2) == 0.67
    assert r1["ttd_median"] == 0.5 and r1["ttc_median"] == 0.6
    assert r1["arpwatch_ttd_median"] == 8.0
    assert s[("full", "B1")]["fp_alerts"] == 2 and s[("full", "B1")]["fp_runs"] == 1
    text = metrics.render(s, errors=1)
    assert "| full | R1 | 3 | 67% |" in text and "Hatalı koşu (sayılmadı): 1" in text


def test_results_csv_resume_skips_done_but_retries_errors(tmp_path):
    path = tmp_path / "results.csv"
    rs.append_row(path, {"profile": "full", "scenario": "R1", "rep": 0, "detected": True})
    rs.append_row(path, {"profile": "full", "scenario": "R2", "rep": 0, "error": "boom"})
    assert rs.done_keys(path) == {("full", "R1", 0)}
    good, bad = metrics.load(path)
    assert len(good) == 1 and len(bad) == 1


def test_baseline_keeps_only_approved_and_run_db_refreshes_ips(tmp_path, monkeypatch):
    live = tmp_path / "live.db"
    conn = db.connect(str(live))
    conn.execute("INSERT INTO devices (mac, ip, status) VALUES (?, '10.20.0.112', 'approved')",
                 (VICTIM,))
    conn.execute("INSERT INTO devices (mac, ip, status) VALUES (?, '10.20.0.130', 'pending')",
                 (ROGUE,))
    conn.execute("INSERT INTO alerts (ts, mac, type, severity) VALUES (1, ?, 'x', 'high')", (ROGUE,))
    conn.close()

    monkeypatch.setattr(rs, "BASELINE_DB", tmp_path / "exp" / "baseline.db")
    monkeypatch.setattr(rs, "RUN_DB", tmp_path / "exp" / "run.db")
    assert rs.prepare_baseline(live, rs.BASELINE_DB) == 1
    rs.fresh_run_db({VICTIM: "10.20.0.190"})
    assert rs.device_ip(VICTIM) == "10.20.0.190"
    assert rs.device_ip(ROGUE) is None and rs.read_alerts() == []

    rs.approve(VICTIM)
    assert rs.approval_applied(VICTIM) is None   # daemon henüz uygulamadı


def test_with_overrides_changes_copy_only():
    cfg = config.load()
    out = config.with_overrides(cfg, "allowlist", "data/experiments/run.db")
    assert out["decision"]["detection_profile"] == "allowlist"
    assert out["database"]["path"].endswith("data/experiments/run.db")
    assert cfg["decision"]["detection_profile"] == config.load()["decision"]["detection_profile"]
    assert config.with_overrides(cfg) == cfg
