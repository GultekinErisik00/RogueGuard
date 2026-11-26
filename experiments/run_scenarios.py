"""7B deney koşucusu: 3 tespit profili × 8 senaryo × N tekrar. Her koşu: sıfırla (rogue'u
`clean`'e döndür, karantinadaki meşru cihazı geri al, rezervasyonu sil, temiz envanter DB
kopyası, rg_block boşalt) → daemon'u profille başlat → dengelenme → senaryo (t0) → alarmları
yokla → results.csv'ye bir satır. Var olan (profil, senaryo, tekrar) satırları atlanır, yani
yarıda kalırsa aynı komutla kaldığı yerden devam eder. Wazuh kapalıyken, tmux içinde çalıştır.

Kullanım (VM'de, ~/rogueguard):
  .venv/bin/python -m experiments.run_scenarios prepare          # baseline DB (bir kez)
  .venv/bin/python -m experiments.run_scenarios run --reps 10    # tam matris
  .venv/bin/python -m experiments.run_scenarios run --reps 1 --profiles full --scenarios R1"""
import argparse
import csv
import logging
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

from experiments import lab_ops, scenarios
from experiments.outcome import evaluate
from rogueguard import config

ROOT = config.ROOT
EXP_DIR = ROOT / "data" / "experiments"
BASELINE_DB = EXP_DIR / "baseline.db"
RUN_DB = EXP_DIR / "run.db"
RESULTS = ROOT / "experiments" / "results.csv"
PROFILES = ("allowlist", "fingerprint", "full")
SETTLE_S = 20            # daemon açıldıktan sonra dengelenme süresi
MIN_OBSERVE_S = 30       # rogue senaryolarında t0'dan sonra en az bu kadar gözlem (arpwatch için)
COLUMNS = ["profile", "scenario", "rep", "victim", "started_at", "t0", "rogue_mac",
           "detected", "alert_types", "first_type", "type_correct", "ttd_s", "ttc_s",
           "fp_alerts", "fp_types", "legit_contained", "pre_alerts", "arpwatch_detected",
           "arpwatch_ttd_s", "approve_s", "ip_moved", "spoof_target", "error"]

log = logging.getLogger("experiments")


# --- Veritabanı ------------------------------------------------------------------------

def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def prepare_baseline(live_db: Path, out: Path) -> int:
    """Canlı DB'den sadece onaylı envanteri tutan temiz bir kopya üretir; satır sayısını döner."""
    out.parent.mkdir(parents=True, exist_ok=True)
    src = _connect(live_db)
    if out.exists():
        out.unlink()
    src.execute(f"VACUUM INTO '{out}'")
    src.close()
    conn = _connect(out)
    conn.execute("DELETE FROM devices WHERE status != 'approved'")
    for table in ("observations", "events", "alerts", "approvals"):
        conn.execute(f"DELETE FROM {table}")
    n = conn.execute("SELECT count(*) FROM devices").fetchone()[0]
    conn.close()
    return n


def fresh_run_db(mac_ips: dict[str, str]) -> None:
    """baseline.db → run.db; cihaz IP'leri canlı duruma göre güncellenir (B2 sonrası kayma)."""
    for suffix in ("", "-wal", "-shm"):
        Path(f"{RUN_DB}{suffix}").unlink(missing_ok=True)
    shutil.copy(BASELINE_DB, RUN_DB)
    conn = _connect(RUN_DB)
    for mac, ip in mac_ips.items():
        conn.execute("UPDATE devices SET ip=NULL WHERE ip=? AND mac!=?", (ip, mac))
        conn.execute("UPDATE devices SET ip=? WHERE mac=?", (ip, mac))
    conn.close()


def read_alerts() -> list[dict[str, Any]]:
    conn = _connect(RUN_DB)
    rows = [dict(r) for r in conn.execute("SELECT ts, mac, type, contained_at FROM alerts")]
    conn.close()
    return rows


def alert_types(mac: str) -> set[str]:
    conn = _connect(RUN_DB)
    out = {r[0] for r in conn.execute("SELECT type FROM alerts WHERE mac=?", (mac,))}
    conn.close()
    return out


def approve(mac: str) -> None:
    conn = _connect(RUN_DB)
    conn.execute("INSERT INTO approvals (ts, mac, decision) VALUES (?, ?, 'approve')",
                 (time.time(), mac))
    conn.close()


def approval_applied(mac: str) -> float | None:
    conn = _connect(RUN_DB)
    row = conn.execute("SELECT applied_at FROM approvals WHERE mac=? ORDER BY id DESC LIMIT 1",
                       (mac,)).fetchone()
    status = conn.execute("SELECT status FROM devices WHERE mac=?", (mac,)).fetchone()
    conn.close()
    ok = row and row[0] and status and status[0] == "approved"
    return row[0] if ok else None


def device_ip(mac: str) -> str | None:
    conn = _connect(RUN_DB)
    row = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
    conn.close()
    return row[0] if row else None


# --- Koşu ------------------------------------------------------------------------------

def done_keys(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    with path.open() as f:
        return {(r["profile"], r["scenario"], int(r["rep"])) for r in csv.DictReader(f)
                if not r.get("error")}


def append_row(path: Path, row: dict[str, Any]) -> None:
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow(row)


def reset_lab(cfg: dict[str, Any], devices: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Koşu öncesi lab'ı bilinen duruma getirir; {cihaz: ip} döndürür."""
    rcfg = cfg["router"]
    lab_ops.kill_stray()
    lab_ops.rogue_reset()
    if lab_ops.has_reservation(rcfg["container"]):
        lab_ops.dnsmasq_clear(rcfg["container"], [])
    ips = lab_ops.ensure_legit(list(devices))
    fresh_run_db({devices[n]["mac"].lower(): ip for n, ip in ips.items()})
    lab_ops.flush_block(rcfg["container"], rcfg["table"], rcfg["block_set"])
    return ips


def wait_for(started: scenarios.Started) -> None:
    if started.wait == "window":
        time.sleep(started.window)
        return
    exp, end = started.expectation, started.t0 + started.window
    while time.time() < end:
        if exp.expected_types & alert_types(exp.target_mac):
            # Aksiyon (contained_at) yazılsın; arpwatch'a da adil süre tanı (~9 sn'de uyarır).
            time.sleep(max(3.0, started.t0 + MIN_OBSERVE_S - time.time()))
            return
        time.sleep(0.5)


def run_one(profile: str, name: str, rep: int, cfg: dict[str, Any],
            devices: dict[str, dict[str, Any]], daemon: lab_ops.Daemon, tmp: Path) -> dict[str, Any]:
    row: dict[str, Any] = {"profile": profile, "scenario": name, "rep": rep,
                           "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    ips = reset_lab(cfg, devices)
    daemon.start(profile, RUN_DB, EXP_DIR / "daemon.log")
    time.sleep(SETTLE_S)
    if not daemon.alive():
        raise RuntimeError("protect daemon dengelenme sırasında kapandı (data/experiments/daemon.log)")
    ctx = scenarios.Ctx(rep, devices, ips, cfg, tmp, approve, approval_applied, alert_types)
    started = scenarios.RUNNERS[name](ctx)
    wait_for(started)

    legit = [n for n in devices if n != started.extra.get("victim") or name.startswith("B")]
    row |= {k: started.extra.get(k, "") for k in ("victim", "rogue_mac", "approve_s",
                                                    "spoof_target")}
    row["legit_contained"] = ";".join(lab_ops.quarantined(legit))
    if name == "B2":
        mac = devices[started.extra["victim"]]["mac"].lower()
        row["ip_moved"] = device_ip(mac) == started.extra["new_ip"]
    daemon.stop()
    row |= evaluate(started.expectation, started.t0, read_alerts(),
                    lab_ops.arpwatch_lines(started.t0))
    row["t0"] = round(started.t0, 3)
    return row


def run_matrix(args: argparse.Namespace) -> None:
    cfg = config.load()
    devices = yaml.safe_load((ROOT / "lab/devices.yaml").read_text())["devices"]
    if not BASELINE_DB.exists():
        raise SystemExit("önce: python -m experiments.run_scenarios prepare")
    done = done_keys(args.out)
    daemon = lab_ops.Daemon(ROOT)
    with tempfile.TemporaryDirectory() as t:
        for rep in range(args.reps):
            for profile in args.profiles:
                for name in args.scenarios:
                    if (profile, name, rep) in done:
                        continue
                    log.info("koşu: %s %s tekrar %d", profile, name, rep)
                    try:
                        row = run_one(profile, name, rep, cfg, devices, daemon, Path(t))
                    except Exception as exc:   # tek koşunun hatası matrisi durdurmasın
                        log.exception("koşu hatası")
                        row = {"profile": profile, "scenario": name, "rep": rep,
                               "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                               "error": str(exc)[:200]}
                    finally:
                        daemon.stop()
                    append_row(args.out, row)
                    log.info("sonuç: %s", {k: row.get(k) for k in
                                           ("detected", "ttd_s", "ttc_s", "fp_alerts", "error")})
    lab_ops.rogue_reset()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare", help="canlı DB'den baseline.db üret")
    r = sub.add_parser("run", help="deney matrisini çalıştır")
    r.add_argument("--reps", type=int, default=10)
    r.add_argument("--profiles", nargs="+", default=list(PROFILES), choices=PROFILES)
    r.add_argument("--scenarios", nargs="+", default=list(scenarios.SCENARIOS),
                   choices=scenarios.SCENARIOS)
    r.add_argument("--out", type=Path, default=RESULTS)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "prepare":
        n = prepare_baseline(Path(config.load()["database"]["path"]), BASELINE_DB)
        print(f"{BASELINE_DB}: {n} onaylı cihaz")
    else:
        run_matrix(args)


if __name__ == "__main__":
    main()
