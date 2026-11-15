"""Bir cihazın parmak izi profilini üretir (aynı yapı hem canlı gözlemden hem de
lab/devices.yaml'dan çıkar, böylece benzerlik karşılaştırması iki kaynakta da çalışır).

Profil: {mac, oui, hostname, opt55, vendor_class, ports, mdns, destinations, interval}
"""
import json
import sqlite3
import statistics
from typing import Any


def oui(mac: str) -> str:
    return mac.lower()[:8]


def build_from_observations(conn: sqlite3.Connection, mac: str) -> dict[str, Any]:
    """Cihazın tüm gözlemlerini (arp, dhcp, mdns, traffic, nmap) tek profile toplar."""
    prof: dict[str, Any] = {"mac": mac, "oui": oui(mac), "hostname": None, "opt55": None,
                            "vendor_class": None, "ports": [], "mdns": [],
                            "destinations": [], "interval": None, "ip": None}
    mdns: set[str] = set()
    dests: set[str] = set()
    intervals: list[float] = []
    for row in conn.execute("SELECT ts, ip, source, data FROM observations WHERE mac=? "
                            "ORDER BY ts", (mac,)):
        d = json.loads(row["data"])
        src = row["source"]
        if src in ("arp", "dhcp") and row["ip"]:
            prof["ip"] = row["ip"]
        if src == "dhcp" and d.get("msg_type") in ("discover", "request"):
            prof["hostname"] = d.get("hostname") or prof["hostname"]
            prof["vendor_class"] = d.get("vendor_class") or prof["vendor_class"]
            prof["opt55"] = d.get("param_req_list") or prof["opt55"]
        elif src == "mdns":
            mdns.update(d.get("services", []))
            prof["hostname"] = prof["hostname"] or d.get("hostname")
        elif src == "traffic":
            dests.update(d.get("destinations", []))
            if d.get("publish_interval_median"):
                intervals.append(d["publish_interval_median"])
        elif src == "nmap":
            prof["ports"] = [f'{p["port"]}/{p["proto"]}' for p in d.get("ports", [])]
    prof["mdns"], prof["destinations"] = sorted(mdns), sorted(dests)
    prof["interval"] = statistics.median(intervals) if intervals else None
    return prof


def build_from_spec(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    """lab/devices.yaml girdisinden profil. option 55 listesi yaml'da yok; DHCP istemcisi
    ve udhcpc_extra, onu belirleyen girdiler olduğu için vekil olarak kullanılır."""
    mqtt = spec.get("mqtt", {})
    interval = mqtt.get("interval") or mqtt.get("mean_interval")
    return {"mac": spec["mac"].lower(), "oui": oui(spec["mac"]), "hostname": spec["hostname"],
            "opt55": [spec["dhcp_client"], *spec.get("udhcpc_extra", [])],
            "vendor_class": spec["vendor_class"],
            "ports": [f'{s["port"]}/tcp' for s in spec.get("services", [])],
            "mdns": sorted(m["type"] for m in spec.get("mdns", [])),
            "destinations": [], "interval": interval, "ip": None}
