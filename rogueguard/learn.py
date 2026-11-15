"""Öğrenme modu: br-iot'u belirli süre dinler, görülen her cihazı nmap ile bir kez tarar,
parmak izini `devices` tablosuna approved olarak yazar, inventory.yaml'a döker ve
rg-router'daki rg_approved setini doldurur. Bu andaki ağ "meşru" kabul edilir."""
import json
import logging
import time
from pathlib import Path

import yaml

from rogueguard import config, db
from rogueguard.containment.router import Router
from rogueguard.discovery.runner import Discovery
from rogueguard.fingerprint import ports, profile

log = logging.getLogger("rogueguard.learn")


def learned_macs(conn, since: float, gw_ip: str) -> dict[str, str]:
    """Öğrenme penceresinde görülen MAC'ler → 'device' ya da 'infrastructure' (router)."""
    found: dict[str, str] = {}
    for r in conn.execute("SELECT DISTINCT mac FROM observations WHERE ts >= ?", (since,)):
        last_ip = conn.execute("SELECT ip FROM observations WHERE mac=? AND source IN "
                               "('arp','dhcp') AND ip IS NOT NULL ORDER BY ts DESC LIMIT 1",
                               (r["mac"],)).fetchone()
        found[r["mac"]] = "infrastructure" if last_ip and last_ip["ip"] == gw_ip else "device"
    return found


def save_device(conn, prof: dict, kind: str, port_rows: list[dict], now: float) -> None:
    dhcp_fp = {"opt55": prof["opt55"], "vendor_class": prof["vendor_class"]}
    conn.execute(
        "INSERT INTO devices (mac, ip, hostname, vendor, dhcp_fp, ports, mdns, destinations, "
        "publish_interval, device_type, status, first_seen, last_seen) "
        "VALUES (?,?,?,?,?,?,?,?,?,?, 'approved', ?, ?) "
        "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, hostname=excluded.hostname, "
        "vendor=excluded.vendor, dhcp_fp=excluded.dhcp_fp, ports=excluded.ports, "
        "mdns=excluded.mdns, destinations=excluded.destinations, "
        "publish_interval=excluded.publish_interval, device_type=excluded.device_type, "
        "status='approved', last_seen=excluded.last_seen",
        (prof["mac"], prof["ip"], prof["hostname"], prof["oui"], _j(dhcp_fp), _j(port_rows),
         _j(prof["mdns"]), _j(prof["destinations"]), prof["interval"],
         "infrastructure" if kind == "infrastructure" else None, now, now))


def _j(obj) -> str:
    return json.dumps(obj, sort_keys=True)


def write_inventory(path: Path, profiles: list[dict]) -> None:
    path.write_text(yaml.safe_dump({"devices": profiles}, sort_keys=True, allow_unicode=True))


def learn(cfg: dict, duration: float, run_nmap: bool = True) -> list[dict]:
    t0 = time.time()
    log.info("öğrenme başladı: %.0f sn", duration)
    disc = Discovery(cfg)
    disc.start()
    disc.run_for(duration)

    conn = db.connect(cfg["database"]["path"])
    gw_ip, subnet = cfg["network"]["iot_gw_ip"], cfg["network"]["iot_subnet"]
    kinds = learned_macs(conn, t0, gw_ip)
    profiles = []
    for mac, kind in sorted(kinds.items()):
        prof = profile.build_from_observations(conn, mac)
        port_rows: list[dict] = []
        if kind == "device" and run_nmap and prof["ip"]:
            log.info("nmap: %s (%s)", mac, prof["ip"])
            port_rows = ports.scan(prof["ip"], subnet)
            db.add_observation(conn, mac, prof["ip"], "nmap", {"ports": port_rows})
            prof["ports"] = [f'{p["port"]}/{p["proto"]}' for p in port_rows]
        save_device(conn, prof, kind, port_rows, time.time())
        profiles.append(prof | {"kind": kind})
        _warn_missing(prof, kind)

    inv = Path(cfg["learn"]["inventory_path"])
    write_inventory(inv if inv.is_absolute() else config.ROOT / inv, profiles)
    approved = [p["ip"] for p in profiles if p["kind"] == "device" and p["ip"]]
    Router(cfg).sync(approved)
    log.info("öğrenme bitti: %d cihaz, %d IP rg_approved'a eklendi", len(profiles), len(approved))
    return profiles


def _warn_missing(prof: dict, kind: str) -> None:
    if kind != "device":
        return
    missing = [k for k in ("hostname", "opt55", "vendor_class") if not prof[k]]
    if missing:
        log.warning("%s için eksik parmak izi alanı: %s (DHCP paketi görülmedi)",
                    prof["mac"], ", ".join(missing))
