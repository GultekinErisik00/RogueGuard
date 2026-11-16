"""Karar motoru (6.3): keşfin her gözlemini envanterle karşılaştırıp alarm üretir.

- Envanterde olmayan MAC → `unknown_device` alarmı, cihaz `pending` yazılır (engelleme yok).
- Envanterdeki (approved) MAC'in DHCP parmak izi (hostname, option 55, vendor class) kendi
  kaydından sapıyorsa → `impersonation`. Skor `fingerprint/compare.py` ile hesaplanır.
- DHCP ACK'te IP değiştiyse cihazın IP'si güncellenir, alarm üretilmez (meşru IP değişimi);
  `on_ip_change` kancası router'daki rg_approved setini yeni IP'ye taşır. MAC için yakın zamanda
  impersonation alarmı varsa IP taşınmaz (taklitçi onaylı sete girmesin).

`detection_profile`: allowlist (sadece MAC) | fingerprint (MAC + DHCP parmak izi) | full.
`full` şimdilik `fingerprint` ile aynıdır; abnormal_behavior (K ardışık pencere) sonra eklenecek.
Alarm yazar ama karantina uygulamaz; aksiyon 6.4'te (containment) alarma bağlanır.
"""
import json
import logging
import sqlite3
import threading
import time
from typing import Any, Callable

from rogueguard import db
from rogueguard.decision.attack_map import ATTACKS
from rogueguard.fingerprint.compare import DEFAULT_WEIGHTS, feature_scores, similarity

log = logging.getLogger("rogueguard.decision")

PROFILES = ("allowlist", "fingerprint", "full")
FP_MSG_TYPES = {"discover", "request"}
IP_SOURCES = {"arp", "dhcp"}                             # IP sadece bunlardan güvenilir okunur
IpChangeHook = Callable[[str, str | None, str], None]    # (mac, eski_ip, yeni_ip)
DHCP_FEATURES = ("hostname", "opt55", "vendor_class")   # DHCP paketinden okunan özellikler


def inventory_profile(row: sqlite3.Row) -> dict[str, Any]:
    """`devices` satırı → compare.py'nin beklediği profil sözlüğü."""
    dhcp_fp = json.loads(row["dhcp_fp"] or "{}")
    ports = json.loads(row["ports"] or "[]")
    return {"mac": row["mac"], "oui": row["vendor"], "hostname": row["hostname"],
            "opt55": dhcp_fp.get("opt55"), "vendor_class": dhcp_fp.get("vendor_class"),
            "ports": [f'{p["port"]}/{p["proto"]}' for p in ports],
            "mdns": json.loads(row["mdns"] or "[]"),
            "destinations": json.loads(row["destinations"] or "[]"),
            "interval": row["publish_interval"]}


def observed_profile(inventory: dict[str, Any], dhcp: dict[str, Any]) -> dict[str, Any]:
    """Envanter profilinin DHCP alanlarını canlı pakettekilerle değiştirir. DISCOVER/REQUEST
    tüm option'ları taşıdığı için pakette olmayan alan da fark sayılır (None)."""
    return inventory | {"hostname": dhcp.get("hostname"), "opt55": dhcp.get("param_req_list"),
                        "vendor_class": dhcp.get("vendor_class")}


class DecisionEngine:
    def __init__(self, cfg: dict[str, Any], conn: sqlite3.Connection | None = None,
                 clock: Callable[[], float] = time.time,
                 on_ip_change: IpChangeHook | None = None) -> None:
        dcfg = cfg["decision"]
        if dcfg["detection_profile"] not in PROFILES:
            raise ValueError(f"detection_profile {dcfg['detection_profile']!r}, "
                             f"beklenen: {', '.join(PROFILES)}")
        self._profile = dcfg["detection_profile"]
        self._match_min = dcfg["match_min"]
        self._cooldown = dcfg["alert_cooldown"]
        self._weights = cfg.get("fingerprint", {}).get("weights", DEFAULT_WEIGHTS)
        self._sensor_ip = cfg["network"]["sensor_iot_ip"]
        self._db_path = cfg.get("database", {}).get("path")
        self._injected = conn
        self._local = threading.local()   # SQLite bağlantısı thread'ler arası paylaşılamaz
        self._clock = clock
        self._on_ip_change = on_ip_change

    def _conn(self) -> sqlite3.Connection:
        if self._injected is not None:
            return self._injected
        if not hasattr(self._local, "conn"):
            self._local.conn = db.connect(self._db_path)
        return self._local.conn

    def on_observation(self, mac: str, ip: str | None, source: str, data: dict[str, Any]) -> None:
        """Recorder'ın her gözlem için çağırdığı kanca."""
        if ip == self._sensor_ip:
            return   # sensörün (host) kendi br-iot adresi cihaz değildir
        conn = self._conn()
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        if row is None:
            self._raise_unknown(conn, mac, ip, data)
            return
        if row["status"] == "pending" and ip and source in IP_SOURCES and ip != row["ip"]:
            conn.execute("UPDATE devices SET ip=?, last_seen=? WHERE mac=?",
                         (ip, self._clock(), mac))   # dashboard onay ekranı IP'yi göstersin
        if row["status"] != "approved" or row["device_type"] == "infrastructure":
            return
        if source == "dhcp" and data.get("msg_type") == "ack" and ip and ip != row["ip"]:
            self._move_ip(conn, row, ip)
        elif (source == "dhcp" and data.get("msg_type") in FP_MSG_TYPES
              and self._profile != "allowlist"):
            self._check_dhcp_fingerprint(conn, row, ip, data)

    def _move_ip(self, conn: sqlite3.Connection, row: sqlite3.Row, new_ip: str) -> None:
        suspect = conn.execute("SELECT 1 FROM alerts WHERE mac=? AND type='impersonation' "
                               "AND ts > ?", (row["mac"], self._clock() - self._cooldown)).fetchone()
        if suspect:
            log.warning("%s için IP %s onaylanmadı: yakın zamanda impersonation alarmı var",
                        row["mac"], new_ip)
            return
        conn.execute("UPDATE devices SET ip=?, last_seen=? WHERE mac=?",
                     (new_ip, self._clock(), row["mac"]))
        log.info("IP değişti %s: %s → %s", row["mac"], row["ip"], new_ip)
        if self._on_ip_change:
            self._on_ip_change(row["mac"], row["ip"], new_ip)

    def sweep(self) -> None:
        """protect başlamadan önce keşifte görülmüş ama envanterde olmayan MAC'leri işaretler."""
        conn = self._conn()
        for r in conn.execute("SELECT DISTINCT mac FROM observations WHERE mac NOT IN "
                              "(SELECT mac FROM devices)").fetchall():
            last = conn.execute("SELECT ip FROM observations WHERE mac=? AND source IN "
                                "('arp','dhcp') AND ip IS NOT NULL ORDER BY ts DESC LIMIT 1",
                                (r["mac"],)).fetchone()
            self.on_observation(r["mac"], last["ip"] if last else None, "sweep", {})

    def _raise_unknown(self, conn: sqlite3.Connection, mac: str, ip: str | None,
                       data: dict[str, Any]) -> None:
        now = self._clock()
        conn.execute("INSERT INTO devices (mac, ip, hostname, vendor, status, first_seen, "
                     "last_seen) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                     (mac, ip, data.get("hostname"), mac[:8], now, now))
        self._alert(conn, mac, ip, "unknown_device", "envanterde olmayan MAC")

    def _check_dhcp_fingerprint(self, conn: sqlite3.Connection, row: sqlite3.Row,
                                ip: str | None, data: dict[str, Any]) -> None:
        inv = inventory_profile(row)
        live = observed_profile(inv, data)
        score = similarity(inv, live, self._weights)
        if score >= self._match_min:
            return
        diff = [k for k, s in feature_scores(inv, live).items() if s < 1.0 and k in DHCP_FEATURES]
        self._alert(conn, row["mac"], ip, "impersonation",
                    f"parmak izi benzerliği {score:.2f} < {self._match_min}; "
                    f"farklı: {', '.join(diff)}")

    def _alert(self, conn: sqlite3.Connection, mac: str, ip: str | None,
               atype: str, reason: str) -> None:
        now = self._clock()
        recent = conn.execute("SELECT 1 FROM alerts WHERE mac=? AND type=? AND ts > ?",
                              (mac, atype, now - self._cooldown)).fetchone()
        if recent:
            return
        attack = ATTACKS[atype]
        conn.execute("INSERT INTO alerts (ts, mac, ip, type, severity, attack_id, action, "
                     "reason, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (now, mac, ip, atype, attack.severity, attack.attack_id, attack.action,
                      reason, now))
        log.warning("ALARM %s %s %s: %s", atype, mac, ip, reason)
