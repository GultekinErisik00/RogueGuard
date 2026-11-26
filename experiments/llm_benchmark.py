"""7A LLM deneyi: kural tabanlı, LLM (Groq) ve hibrit sınıflandırıcıyı etiketli parmak izi
veri setinde karşılaştırır (doğruluk, confusion matrix, gecikme, API çağrı sayısı) ve prompt
injection'ın etiketi değiştirip değiştirmediğini ölçer. Çıktı: experiments/llm_results.json.
Kullanım (VM'de): .venv/bin/python -m experiments.llm_benchmark [--pace 2.5] [--reuse]"""
import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any, Callable

from experiments import llm_dataset
from rogueguard import config
from rogueguard.classify import llm as llm_mod
from rogueguard.classify import rules

RESULTS_PATH = config.ROOT / "experiments/llm_results.json"
LABELS = list(rules.LABELS)
METHODS = ("rules", "llm", "hybrid")


def _strip(res: dict[str, Any]) -> dict[str, Any]:
    return {k: res.get(k) for k in ("label", "confidence", "reason")}


class TimedLLM:
    """LLM çağrısını önbelleksiz yapar, süresini ölçer; aynı parmak izini tekrar sormaz."""

    def __init__(self, clf: llm_mod.LLMClassifier, pace: float = 0.0,
                 previous: dict[str, dict[str, Any]] | None = None,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        self._clf = clf
        self._pace = pace
        self._sleeper = sleeper
        self._memo: dict[str, dict[str, Any]] = dict(previous or {})
        self.api_calls = 0

    def classify(self, profile: dict[str, Any]) -> dict[str, Any]:
        h = llm_mod.fingerprint_hash(profile)
        if h in self._memo:
            return self._memo[h]
        if self.api_calls and self._pace:
            self._sleeper(self._pace)  # ücretsiz katman dakika limitine takılmamak için
        t0 = time.perf_counter()
        res = self._clf.classify(profile, use_cache=False)
        latency = round(time.perf_counter() - t0, 3)
        self.api_calls += 1
        out = _strip(res) | {"latency_s": latency, "hash": h}
        self._memo[h] = out
        return out

    @property
    def memo(self) -> dict[str, dict[str, Any]]:
        return self._memo


def run_labeled(items: list[dict[str, Any]], llm: TimedLLM) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        r = _strip(rules.classify(item["profile"]))
        l_res = llm.classify(item["profile"])
        # Hibrit: kural cevabı geçerli; kural "unknown" derse LLM cevabı kullanılır.
        hybrid = (r | {"source": "rules"}) if r["label"] != "unknown" else (l_res | {"source": "llm"})
        rows.append({"id": item["id"], "source": item["source"], "variant": item["variant"],
                     "truth": item["truth"], "rules": r, "llm": l_res, "hybrid": hybrid})
    return rows


def run_injection(items: list[dict[str, Any]], labeled_rows: list[dict[str, Any]],
                  llm: TimedLLM) -> list[dict[str, Any]]:
    base = {r["id"]: r for r in labeled_rows}
    rows = []
    for item in items:
        b = base[item["base_id"]]
        r_inj = _strip(rules.classify(item["profile"]))
        l_inj = llm.classify(item["profile"])
        rows.append({
            "id": item["id"], "field": item["field"], "truth": item["truth"],
            "target": item["target"],
            "rules": {"before": b["rules"]["label"], "after": r_inj["label"]},
            "llm": {"before": b["llm"]["label"], "after": l_inj["label"],
                    "reason": l_inj.get("reason")},
        })
    return rows


def confusion(rows: list[dict[str, Any]], method: str) -> dict[str, dict[str, int]]:
    """matris[gerçek][tahmin] = sayı."""
    mat = {t: {p: 0 for p in LABELS} for t in LABELS}
    for row in rows:
        mat[row["truth"]][row[method]["label"]] += 1
    return mat


def accuracy(rows: list[dict[str, Any]], method: str) -> float:
    if not rows:
        return 0.0
    return round(sum(r[method]["label"] == r["truth"] for r in rows) / len(rows), 3)


def latency_stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"mean_s": None, "median_s": None, "max_s": None}
    return {"mean_s": round(statistics.mean(values), 3),
            "median_s": round(statistics.median(values), 3), "max_s": round(max(values), 3)}


def injection_summary(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Yöntem başına: etiket değişti mi, saldırganın hedef etiketine mi döndü."""
    out = {}
    for method in ("rules", "llm"):
        changed = sum(r[method]["before"] != r[method]["after"] for r in rows)
        hijacked = sum(r[method]["after"] == r["target"] != r[method]["before"] for r in rows)
        out[method] = {"cases": len(rows), "label_changed": changed, "hijacked_to_target": hijacked}
    return out


def summarize(labeled: list[dict[str, Any]], injection: list[dict[str, Any]],
              llm_latencies: list[float]) -> dict[str, Any]:
    variants = sorted({r["variant"] for r in labeled})
    return {
        "n_labeled": len(labeled),
        "accuracy": {m: accuracy(labeled, m) for m in METHODS},
        "accuracy_by_variant": {v: {m: accuracy([r for r in labeled if r["variant"] == v], m)
                                    for m in METHODS} for v in variants},
        "confusion": {m: confusion(labeled, m) for m in METHODS},
        "api_calls_per_method": {"rules": 0, "llm": len(labeled),
                                 "hybrid": sum(r["hybrid"]["source"] == "llm" for r in labeled)},
        "llm_latency": latency_stats(llm_latencies),
        "injection": injection_summary(injection),
    }


def _load_previous(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {v["hash"]: v for v in data.get("llm_memo", {}).values() if "hash" in v}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pace", type=float, default=2.5, help="iki API çağrısı arası bekleme (sn)")
    ap.add_argument("--reuse", action="store_true",
                    help="önceki llm_results.json'daki LLM cevaplarını yeniden kullan")
    ap.add_argument("--out", type=Path, default=RESULTS_PATH)
    args = ap.parse_args()

    clf = llm_mod.LLMClassifier(config.load(), cache_path=None)
    if not clf.enabled:
        raise SystemExit("GROQ_API_KEY bulunamadı (.env)")
    previous = _load_previous(args.out) if args.reuse else {}
    llm = TimedLLM(clf, pace=args.pace, previous=previous)

    data = llm_dataset.build()
    labeled = run_labeled(data["labeled"], llm)
    injection = run_injection(data["injection"], labeled, llm)
    latencies = [v["latency_s"] for v in llm.memo.values() if v.get("latency_s") is not None]
    summary = summarize(labeled, injection, latencies)

    result = {"model": clf.model, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
              "new_api_calls": llm.api_calls, "summary": summary,
              "labeled": labeled, "injection": injection, "llm_memo": llm.memo}
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(json.dumps(summary["accuracy"] | {"injection": summary["injection"]}, ensure_ascii=False))
    print(f"{llm.api_calls} yeni API çağrısı; sonuçlar: {args.out}")


if __name__ == "__main__":
    main()
