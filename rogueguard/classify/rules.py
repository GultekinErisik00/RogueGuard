"""Kural tabanlı cihaz türü sınıflandırıcı (6.7): port, mDNS servisi, OUI üreticisi,
vendor_class, hostname ve yayın aralığından cihaz türünü tahmin eder.
Etiketler: camera, printer, smart_plug, sensor, thermostat, unknown."""
from typing import Any

LABELS = ("camera", "printer", "smart_plug", "sensor", "thermostat", "unknown")

# OUI → (etiket, puan, açıklama)
OUI_RULES: dict[str, tuple[str, float, str]] = {
    "00:40:8c": ("camera", 2.0, "OUI: Axis"),
    "00:1b:a9": ("printer", 2.0, "OUI: Brother"),
    "00:11:50": ("smart_plug", 2.0, "OUI: Belkin"),
    "00:4b:12": ("sensor", 2.0, "OUI: Espressif"),
    "44:61:32": ("thermostat", 3.0, "OUI: ecobee"),
}

MDNS_RULES: dict[str, tuple[str, float]] = {
    "_rtsp._tcp": ("camera", 3.0),
    "_ipp._tcp": ("printer", 3.0),
    "_printer._tcp": ("printer", 3.0),
    "_hap._tcp": ("thermostat", 2.0),
}

PORT_RULES: dict[int, tuple[str, float]] = {
    554: ("camera", 3.0),
    631: ("printer", 3.0),
    9100: ("printer", 3.0),
    49153: ("smart_plug", 3.0),
    9999: ("smart_plug", 3.0),
}

KEYWORD_RULES: dict[str, tuple[str, ...]] = {
    "camera": ("camera", "axis", "ipcam", "rtsp", "hikvision", "dahua", "reolink"),
    "printer": ("printer", "brother", "ipp", "jetdirect", "laserjet", "epson", "canon"),
    "smart_plug": ("wemo", "belkin", "plug", "outlet", "socket", "kasa", "shelly", "tasmota"),
    "sensor": ("sensor", "esp32", "esp8266", "espressif", "sht31", "dht", "temp", "humid"),
    "thermostat": ("thermostat", "ecobee", "nest", "honeywell", "hvac"),
}


def _port_numbers(ports: list[Any]) -> set[int]:
    nums: set[int] = set()
    for p in ports or []:
        if isinstance(p, int):
            nums.add(p)
        elif isinstance(p, dict) and "port" in p:
            nums.add(int(p["port"]))
        elif isinstance(p, str):
            head = p.split("/", 1)[0]
            if head.isdigit():
                nums.add(int(head))
    return nums


def _text_blob(profile: dict[str, Any]) -> str:
    parts = [profile.get("hostname") or "", profile.get("vendor_class") or ""]
    for p in profile.get("ports") or []:
        if isinstance(p, dict):
            parts.extend([str(p.get("service") or ""), str(p.get("banner") or "")])
    return " ".join(parts).lower()


def classify(profile: dict[str, Any]) -> dict[str, Any]:
    """Cihaz profil sözlüğünden {label, confidence, reason} döndürür."""
    scores: dict[str, float] = {k: 0.0 for k in LABELS if k != "unknown"}
    reasons: dict[str, list[str]] = {k: [] for k in scores}

    oui = (profile.get("oui") or (profile.get("mac") or "")[:8]).lower()
    if oui in OUI_RULES:
        lbl, pts, desc = OUI_RULES[oui]
        scores[lbl] += pts
        reasons[lbl].append(desc)

    mdns_list = [m.lower() for m in (profile.get("mdns") or [])]
    for svc in mdns_list:
        if svc in MDNS_RULES:
            lbl, pts = MDNS_RULES[svc]
            scores[lbl] += pts
            reasons[lbl].append(f"mDNS:{svc}")

    ports = _port_numbers(profile.get("ports") or [])
    for port in sorted(ports):
        if port in PORT_RULES:
            lbl, pts = PORT_RULES[port]
            scores[lbl] += pts
            reasons[lbl].append(f"port:{port}")

    text = _text_blob(profile)
    for lbl, words in KEYWORD_RULES.items():
        hits = [w for w in words if w in text]
        if hits:
            scores[lbl] += 2.0
            reasons[lbl].append("metin:" + "/".join(hits[:3]))

    # Açık portu ve mDNS'i olmayan, kısa periyotlu MQTT yayıncısı genelde sensördür.
    interval = profile.get("interval")
    if not ports and not mdns_list and interval is not None and 5 <= interval <= 60:
        scores["sensor"] += 1.5
        reasons["sensor"].append(f"sessiz+MQTT({interval:.0f}s)")

    best_score = max(scores.values())
    if best_score < 2.0:
        return {"label": "unknown", "confidence": 0.0, "reason": "yeterli kural eşleşmesi yok"}

    winners = [lbl for lbl, sc in scores.items() if sc == best_score]
    if len(winners) > 1:
        return {"label": "unknown", "confidence": 0.0,
                "reason": "eşit skor: " + ", ".join(sorted(winners))}

    label = winners[0]
    confidence = round(min(0.99, 0.5 + best_score / 10.0), 2)
    return {"label": label, "confidence": confidence, "reason": "; ".join(reasons[label])}
