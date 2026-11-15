"""İki cihaz profili arasındaki benzerlik skoru (0..1). Özellik bazında karşılaştırır:
OUI, hostname, option 55 sırası ve vendor class birebir; port/mDNS/hedef kümeleri Jaccard;
yayın aralığı toleransla. Ağırlıklar config.yaml `fingerprint.weights` içindedir."""
from typing import Any

DEFAULT_WEIGHTS = {"oui": 1.0, "hostname": 1.0, "opt55": 1.0, "vendor_class": 1.0,
                   "ports": 1.0, "mdns": 1.0, "destinations": 0.5, "interval": 0.5}
INTERVAL_TOLERANCE = 0.3     # aralıklar %30 içinde ise eşleşir


def jaccard(a: list, b: list) -> float:
    sa, sb = set(a), set(b)
    return 1.0 if not sa and not sb else len(sa & sb) / len(sa | sb)


def _same(a: Any, b: Any) -> float:
    return 1.0 if a == b else 0.0


def _interval(a: float | None, b: float | None) -> float:
    if a is None or b is None:
        return 1.0 if a is None and b is None else 0.0
    return 1.0 if abs(a - b) <= INTERVAL_TOLERANCE * max(a, b) else 0.0


def feature_scores(a: dict[str, Any], b: dict[str, Any]) -> dict[str, float]:
    return {"oui": _same(a["oui"], b["oui"]),
            "hostname": _same(a["hostname"], b["hostname"]),
            "opt55": _same(a["opt55"], b["opt55"]),
            "vendor_class": _same(a["vendor_class"], b["vendor_class"]),
            "ports": jaccard(a["ports"], b["ports"]),
            "mdns": jaccard(a["mdns"], b["mdns"]),
            "destinations": jaccard(a["destinations"], b["destinations"]),
            "interval": _interval(a["interval"], b["interval"])}


def similarity(a: dict[str, Any], b: dict[str, Any],
               weights: dict[str, float] | None = None) -> float:
    w = weights or DEFAULT_WEIGHTS
    scores = feature_scores(a, b)
    return sum(w[k] * s for k, s in scores.items()) / sum(w[k] for k in scores)
