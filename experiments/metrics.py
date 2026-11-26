"""7B: experiments/results.csv'yi profil × senaryo bazında özetler: tespit oranı, tür doğruluğu,
ortalama/medyan TTD ve TTC, yanlış pozitif alarm, yanlışlıkla karantinaya alınan meşru cihaz
ve arpwatch karşılaştırması. Hatalı (error) koşular sayılmaz, ayrıca raporlanır.
Kullanım: .venv/bin/python -m experiments.metrics [results.csv]"""
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from experiments.scenarios import SCENARIOS

RESULTS = Path(__file__).resolve().parent / "results.csv"
PROFILES = ("allowlist", "fingerprint", "full")
ATTACKS = {"R1", "R2", "R3", "R4"}


def _bool(v: str) -> bool:
    return v.strip().lower() == "true"


def _floats(rows: list[dict[str, str]], key: str) -> list[float]:
    return [float(r[key]) for r in rows if r.get(key) not in (None, "", "None")]


def _stat(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    return round(statistics.mean(values), 2), round(statistics.median(values), 2)


def load(path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    with path.open() as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if not r.get("error")], [r for r in rows if r.get("error")]


def summarize(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        groups[(r["profile"], r["scenario"])].append(r)
    out = {}
    for key, g in groups.items():
        n = len(g)
        ttd, ttc = _stat(_floats(g, "ttd_s")), _stat(_floats(g, "ttc_s"))
        aw = [r for r in g if _bool(r["arpwatch_detected"])]
        out[key] = {
            "n": n,
            "detect_rate": sum(_bool(r["detected"]) for r in g) / n,
            "type_rate": sum(_bool(r["type_correct"]) for r in g) / n,
            "ttd_mean": ttd[0], "ttd_median": ttd[1],
            "ttc_mean": ttc[0], "ttc_median": ttc[1],
            "fp_alerts": sum(int(r["fp_alerts"] or 0) for r in g),
            "fp_runs": sum(int(r["fp_alerts"] or 0) > 0 for r in g),
            "legit_contained": sum(bool(r["legit_contained"]) for r in g),
            "arpwatch_rate": len(aw) / n,
            "arpwatch_ttd_median": _stat(_floats(aw, "arpwatch_ttd_s"))[1],
            "approve_median": _stat(_floats(g, "approve_s"))[1],
            "ip_moved": sum(_bool(r.get("ip_moved", "")) for r in g),
        }
    return out


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def _num(x: float | None) -> str:
    return "—" if x is None else f"{x:.2f}"


def render(summary: dict[tuple[str, str], dict[str, Any]], errors: int = 0) -> str:
    lines = ["### Saldırılar (R1–R4)",
             "| Profil | Senaryo | n | Tespit | Tür doğru | TTD ort/med (sn) | TTC ort/med (sn) "
             "| YP alarm | Meşru karantina | arpwatch | arpwatch TTD med |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for p in PROFILES:
        for s in SCENARIOS:
            m = summary.get((p, s))
            if not m or s not in ATTACKS:
                continue
            lines.append(f"| {p} | {s} | {m['n']} | {_pct(m['detect_rate'])} | "
                         f"{_pct(m['type_rate'])} | {_num(m['ttd_mean'])} / {_num(m['ttd_median'])} | "
                         f"{_num(m['ttc_mean'])} / {_num(m['ttc_median'])} | {m['fp_alerts']} | "
                         f"{m['legit_contained']} | {_pct(m['arpwatch_rate'])} | "
                         f"{_num(m['arpwatch_ttd_median'])} |")
    lines += ["", "### Normal olaylar (B1–B4)",
              "| Profil | Senaryo | n | YP alarm (koşu) | Meşru karantina | arpwatch uyarısı | Not |",
              "|---|---|---|---|---|---|---|"]
    for p in PROFILES:
        for s in SCENARIOS:
            m = summary.get((p, s))
            if not m or s in ATTACKS:
                continue
            note = ""
            if s == "B2":
                note = f"IP taşındı {m['ip_moved']}/{m['n']}"
            elif s == "B3":
                note = (f"unknown_device {_pct(m['detect_rate'])}, onay medyan "
                        f"{_num(m['approve_median'])} sn")
            lines.append(f"| {p} | {s} | {m['n']} | {m['fp_alerts']} ({m['fp_runs']}) | "
                         f"{m['legit_contained']} | {_pct(m['arpwatch_rate'])} | {note} |")
    if errors:
        lines += ["", f"Hatalı koşu (sayılmadı): {errors}"]
    return "\n".join(lines)


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS
    rows, errors = load(path)
    print(render(summarize(rows), len(errors)))


if __name__ == "__main__":
    main()
