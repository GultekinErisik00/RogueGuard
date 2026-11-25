"""Dashboard veri katmanı: SQLite tablolarını okur ve yalnızca `approvals` tablosuna
approve/reject kararı yazar. Streamlit arayüzünden ayrı tutulur ki birim testleri
Streamlit sunucusu olmadan çalışabilsin."""
import json
import sqlite3
import time
from typing import Any

from rogueguard.classify import rules
from rogueguard.classify.llm import LLMClassifier


def device_profile_from_row(r: sqlite3.Row) -> dict[str, Any]:
    """`devices` satırından sınıflandırıcıların beklediği profil sözlüğünü çıkarır."""
    dhcp_fp = json.loads(r["dhcp_fp"] or "{}")
    ports = json.loads(r["ports"] or "[]")
    return {
        "mac": r["mac"],
        "oui": r["vendor"] or r["mac"][:8],
        "hostname": r["hostname"],
        "opt55": dhcp_fp.get("opt55"),
        "vendor_class": dhcp_fp.get("vendor_class"),
        "ports": ports,
        "mdns": json.loads(r["mdns"] or "[]"),
        "interval": r["publish_interval"],
    }


def load_devices(conn: sqlite3.Connection,
                 llm: LLMClassifier | None = None) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT mac, ip, hostname, vendor, dhcp_fp, ports, mdns, publish_interval, device_type, "
        "status, first_seen, last_seen FROM devices ORDER BY status, hostname, mac"
    ).fetchall()
    out = []
    for r in rows:
        ports = json.loads(r["ports"] or "[]")
        port_list = [f'{p["port"]}/{p.get("proto", "tcp")}' for p in ports if isinstance(p, dict)]
        mdns_list = json.loads(r["mdns"] or "[]")
        prof = device_profile_from_row(r)
        if r["device_type"] == "infrastructure":
            rule_label, llm_label = "infrastructure", "—"
        else:
            rule_label = rules.classify(prof)["label"]
            cached = llm.get_cached(prof) if llm is not None else None
            llm_label = f"{cached['label']} ({cached['confidence']:.2f})" if cached else "—"
        out.append({
            "mac": r["mac"],
            "ip": r["ip"] or "—",
            "hostname": r["hostname"] or "—",
            "oui": r["vendor"] or r["mac"][:8],
            "rule_type": rule_label,
            "llm_type": llm_label,
            "status": r["status"],
            "ports": ", ".join(port_list) or "—",
            "mdns": ", ".join(mdns_list) or "—",
            "publish_interval": round(r["publish_interval"], 1) if r["publish_interval"] else None,
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
        })
    return out


def load_pending(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Onay bekleyen (status='pending') cihazlar ve varsa uygulanmamış kararları."""
    queued = {
        r["mac"]: r["decision"]
        for r in conn.execute(
            "SELECT mac, decision FROM approvals WHERE applied_at IS NULL ORDER BY id"
        ).fetchall()
    }
    rows = conn.execute(
        "SELECT mac, ip, hostname, vendor, first_seen, last_seen FROM devices "
        "WHERE status='pending' ORDER BY first_seen DESC"
    ).fetchall()
    return [{
        "mac": r["mac"],
        "ip": r["ip"] or "—",
        "hostname": r["hostname"] or "—",
        "oui": r["vendor"] or r["mac"][:8],
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "queued_decision": queued.get(r["mac"]),
    } for r in rows]


def load_alerts(conn: sqlite3.Connection, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, ts, mac, ip, type, severity, attack_id, action, reason, "
        "detected_at, contained_at FROM alerts ORDER BY ts DESC, id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    out = []
    for r in rows:
        ttc = (round(r["contained_at"] - r["detected_at"], 2)
               if r["contained_at"] and r["detected_at"] else None)
        out.append({
            "id": r["id"],
            "ts": r["ts"],
            "type": r["type"],
            "attack_id": r["attack_id"] or "—",
            "severity": r["severity"],
            "mac": r["mac"],
            "ip": r["ip"] or "—",
            "action": r["action"] or "—",
            "reason": r["reason"] or "—",
            "ttc_s": ttc,
        })
    return out


def submit_approval(conn: sqlite3.Connection, mac: str, decision: str,
                    ts: float | None = None) -> int:
    """Dashboard'dan gelen Onayla/Reddet kararını `approvals` tablosuna yazar."""
    if decision not in ("approve", "reject"):
        raise ValueError(f"geçersiz karar: {decision!r}")
    cur = conn.execute(
        "INSERT INTO approvals (ts, mac, decision) VALUES (?, ?, ?)",
        (ts or time.time(), mac.lower(), decision),
    )
    return int(cur.lastrowid)
