"""experiments/llm_results.json'dan rapor için Markdown tabloları üretir (doğruluk,
varyant bazında doğruluk, hatalı tahminler, confusion matrix, gecikme, prompt injection).
Kullanım: .venv/bin/python -m experiments.llm_report > tablolar.md"""
from collections import Counter
import json
from typing import Any

from experiments.llm_benchmark import LABELS, METHODS, RESULTS_PATH

SHORT = {"camera": "cam", "printer": "prn", "smart_plug": "plug", "sensor": "sens",
         "thermostat": "thermo", "unknown": "unk"}


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def accuracy_table(s: dict[str, Any], counts: Counter) -> list[str]:
    lines = ["| Varyant | n | Kurallar | LLM | Hibrit |", "|---|---|---|---|---|"]
    for v, acc in s["accuracy_by_variant"].items():
        lines.append(f"| {v} | {counts[v]} | " + " | ".join(_pct(acc[m]) for m in METHODS) + " |")
    lines.append(f"| **Toplam** | {s['n_labeled']} | "
                 + " | ".join(f"**{_pct(s['accuracy'][m])}**" for m in METHODS) + " |")
    return lines


def confusion_table(mat: dict[str, dict[str, int]]) -> list[str]:
    lines = ["| gerçek \\ tahmin | " + " | ".join(SHORT[p] for p in LABELS) + " |",
             "|---" * (len(LABELS) + 1) + "|"]
    for t in LABELS:
        if sum(mat[t].values()) == 0:
            continue
        cells = [f"**{mat[t][p]}**" if p == t and mat[t][p] else str(mat[t][p] or "·")
                 for p in LABELS]
        lines.append(f"| {t} | " + " | ".join(cells) + " |")
    return lines


def _flip(side: dict[str, str], target: str) -> str:
    mark = " ⚠" if side["after"] == target != side["before"] else ""
    return f"{side['before']}→{side['after']}{mark}"


def injection_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["| Örnek | Alan | Hedef | Kurallar (önce→sonra) | LLM (önce→sonra) |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['id'].split(':inj-')[0]} | {r['field']} | {r['target']} | "
                     f"{_flip(r['rules'], r['target'])} | {_flip(r['llm'], r['target'])} |")
    return lines


def errors_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["| Örnek | Gerçek | Kurallar | LLM | Hibrit |", "|---|---|---|---|---|"]
    for r in rows:
        if all(r[m]["label"] == r["truth"] for m in METHODS):
            continue
        cells = [r[m]["label"] if r[m]["label"] == r["truth"] else f"**{r[m]['label']}**"
                 for m in METHODS]
        lines.append(f"| {r['id']} | {r['truth']} | " + " | ".join(cells) + " |")
    return lines


def render(data: dict[str, Any]) -> str:
    s = data["summary"]
    counts = Counter(r["variant"] for r in data["labeled"])
    lat, calls, inj = s["llm_latency"], s["api_calls_per_method"], s["injection"]
    out = [f"Model: `{data['model']}` · Koşu: {data['generated_at']}", "",
           "### Doğruluk", *accuracy_table(s, counts), "",
           f"API çağrısı (etiketli set): kurallar {calls['rules']}, LLM {calls['llm']}, "
           f"hibrit {calls['hybrid']}. LLM gecikmesi (injection dahil tüm çağrılar): ort. {lat['mean_s']} sn, "
           f"medyan {lat['median_s']} sn, en çok {lat['max_s']} sn.", "",
           "### Hatalı tahminler", *errors_table(data["labeled"]), ""]
    for m in METHODS:
        out += [f"### Confusion matrix — {m}", *confusion_table(s["confusion"][m]), ""]
    out += ["### Prompt injection",
            f"Kurallar: {inj['rules']['label_changed']}/{inj['rules']['cases']} etiket değişti, "
            f"{inj['rules']['hijacked_to_target']} hedefe döndü. "
            f"LLM: {inj['llm']['label_changed']}/{inj['llm']['cases']} etiket değişti, "
            f"{inj['llm']['hijacked_to_target']} hedefe döndü (⚠ = saldırganın hedef etiketi).", "",
            *injection_table(data["injection"])]
    return "\n".join(out)


if __name__ == "__main__":
    print(render(json.loads(RESULTS_PATH.read_text())))
