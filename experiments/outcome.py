"""7B: tek bir deney koşusunun sonucunu hesaplar (saf fonksiyonlar, lab erişimi yok).
Girdi: senaryonun beklentisi, t0, koşu sonunda DB'deki alarmlar, arpwatch günlüğü.
Çıktı: results.csv'ye yazılan satırın ölçüm alanları (yakalandı mı, tür doğru mu, TTD, TTC,
yanlış pozitif sayısı, arpwatch karşılaştırması)."""
import re
from dataclasses import dataclass, field
from typing import Any

ARPWATCH_KINDS = ("new station", "changed ethernet address", "flip flop",
                  "reused old ethernet address", "ethernet mismatch")
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}\b", re.IGNORECASE)


@dataclass(frozen=True)
class Expectation:
    """Senaryonun ölçüt tanımı: hangi MAC hangi alarm türleriyle yakalanmalı."""
    target_mac: str | None                 # rogue / yeni cihaz MAC'i (B1/B2/B4'te None)
    expected_types: frozenset[str] = field(default_factory=frozenset)  # boş = alarm beklenmez


def norm_mac(mac: str) -> str:
    """arpwatch baştaki sıfırları atar (0:40:8c:...); karşılaştırma için iki haneye tamamlar."""
    return ":".join(part.zfill(2) for part in mac.lower().split(":"))


def arpwatch_hits(lines: list[tuple[float, str]], mac: str | None) -> list[tuple[float, str]]:
    """arpwatch satırlarından hedef MAC'i anan uyarıları (zaman, tür) döndürür."""
    hits = []
    for ts, text in lines:
        kind = next((k for k in ARPWATCH_KINDS if k in text), None)
        if kind is None:
            continue
        macs = {norm_mac(m) for m in _MAC_RE.findall(text)}
        if mac is None or norm_mac(mac) in macs:
            hits.append((ts, kind))
    return hits


def evaluate(exp: Expectation, t0: float, alerts: list[dict[str, Any]],
             arpwatch_lines: list[tuple[float, str]]) -> dict[str, Any]:
    """Alarmlar: {ts, mac, type, contained_at} sözlükleri. t0 öncesi alarmlar (dengelenme
    gürültüsü) ayrı sayılır, tespite karışmaz."""
    before = [a for a in alerts if a["ts"] < t0]
    after = sorted((a for a in alerts if a["ts"] >= t0), key=lambda a: a["ts"])
    target = norm_mac(exp.target_mac) if exp.target_mac else None
    mine = [a for a in after if target and norm_mac(a["mac"]) == target]
    others = [a for a in after if not target or norm_mac(a["mac"]) != target]
    hits = [a for a in mine if a["type"] in exp.expected_types]
    contained = [a["contained_at"] for a in mine if a.get("contained_at")]

    aw = arpwatch_hits([(ts, t) for ts, t in arpwatch_lines if ts >= t0], exp.target_mac)
    return {
        "detected": bool(hits),
        "alert_types": ";".join(dict.fromkeys(a["type"] for a in mine)),
        "first_type": mine[0]["type"] if mine else "",
        "type_correct": bool(mine) and mine[0]["type"] in exp.expected_types,
        "ttd_s": round(hits[0]["ts"] - t0, 3) if hits else None,
        "ttc_s": round(min(contained) - t0, 3) if contained else None,
        "fp_alerts": len(others),
        "fp_types": ";".join(sorted({a["type"] for a in others})),
        "pre_alerts": len(before),
        "arpwatch_detected": bool(aw),
        "arpwatch_ttd_s": round(aw[0][0] - t0, 3) if aw else None,
    }
