"""Karar motoru (6.3): keşfin her gözlemini envanterle karşılaştırıp alarm üretir.

- Envanterde olmayan MAC → `unknown_device` alarmı, cihaz `pending` yazılır (engelleme yok).
- Envanterdeki (approved) MAC'in DHCP parmak izi (hostname, option 55, vendor class) kendi
  kaydından sapıyorsa → `impersonation`. Skor `fingerprint/compare.py` ile hesaplanır.
- DHCP ACK'te IP değiştiyse cihazın IP'si güncellenir, alarm üretilmez (meşru IP değişimi);
  `on_ip_change` kancası router'daki rg_approved setini yeni IP'ye taşır. MAC için yakın zamanda
  impersonation alarmı varsa IP taşınmaz (taklitçi onaylı sete girmesin).

`detection_profile`: allowlist (sadece MAC) | fingerprint (MAC + DHCP parmak izi) |
full (fingerprint + ARP zehirleme + tarama + davranış sapması; arp_guard.py, scan.py, behavior.py).
Alarm yazar; aksiyonu `on_alert` kancası üzerinden containment/actions.py uygular.
"""
import json
import logging
import sqlite3
import threading
import time
from typing import Any, Callable

from rogueguard import db
from rogueguard.decision.arp_guard import spoof_reason
from rogueguard.decision.attack_map import ATTACKS
from rogueguard.decision.behavior import BehaviorMonitor
from rogueguard.decision.scan import ScanDetector
from rogueguard.fingerprint.compare import DEFAULT_WEIGHTS, feature_scores, similarity

log = logging.getLogger("rogueguard.decision")

PROFILES = ("allowlist", "fingerprint", "full")
FP_MSG_TYPES = {"discover", "request"}
IP_SOURCES = {"arp", "dhcp"}                             # IP sadece bunlardan güvenilir okunur
IpChangeHook = Callable[[str, str | None, str], None]    # (mac, eski_ip, yeni_ip)
AlertHook = Callable[[sqlite3.Connection, int], None]    # (bağlantı, alarm id) → aksiyon (6.4)
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
                 on_ip_change: IpChangeHook | None = None,
                 on_alert: AlertHook | None = None) -> None:
        dcfg = cfg["decision"]
        if dcfg["detection_profile"] not in PROFILES:
            raise ValueError(f"detection_profile {dcfg['detection_profile']!r}, "
                             f"beklenen: {', '.join(PROFILES)}")
        self._profile = dcfg["detection_profile"]
        self._match_min = dcfg["match_min"]
        self._cooldown = dcfg["alert_cooldown"]
        self._weights = cfg.get("fingerprint", {}).get("weights", DEFAULT_WEIGHTS)
        self._sensor_ip = cfg["network"]["sensor_iot_ip"]
        self._scan = ScanDetector(dcfg.get("scan_window", 30), dcfg.get("scan_arp_targets", 10),
                                  dcfg.get("scan_syn_targets", 15))
        self._behavior = BehaviorMonitor(
            dcfg.get("behavior_windows", 3), cfg.get("discovery", {}).get("traffic_window", 60),
            dcfg.get("rate_factor", 3), dcfg.get("rate_slack", 5),
            {self._sensor_ip, cfg["network"].get("iot_gw_ip")})
        self._db_path = cfg.get("database", {}).get("path")
        self._injected = conn
        self._local = threading.local()   # SQLite bağlantısı thread'ler arası paylaşılamaz
        self._clock = clock
        self._on_ip_change = on_ip_change
        self._on_alert = on_alert

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
            # Dashboard onay ekranı IP'yi göstersin. Onaylı bir cihazın IP'si yazılmaz:
            # sahte ARP ile "ağ geçidi benim" diyen cihazın kaydı o IP'yi almasın.
            taken = conn.execute("SELECT 1 FROM devices WHERE ip=? AND status='approved'",
                                 (ip,)).fetchone()
            if not taken:
                conn.execute("UPDATE devices SET ip=?, last_seen=? WHERE mac=?",
                             (ip, self._clock(), mac))
        if row["status"] != "approved" or row["device_type"] == "infrastructure":
            return
        if source == "dhcp" and data.get("msg_type") == "ack" and ip and ip != row["ip"]:
            self._move_ip(conn, row, ip)
        elif (source == "dhcp" and data.get("msg_type") in FP_MSG_TYPES
              and self._profile != "allowlist"):
            self._check_dhcp_fingerprint(conn, row, ip, data)
        elif source == "traffic" and self._profile == "full":
            reason = self._behavior.check(mac, inventory_profile(row), data)
            if reason:
                self._alert(conn, mac, ip or row["ip"], "abnormal_behavior", reason)

    def on_arp(self, ts: float, ether_src: str, hwsrc: str, psrc: str, pdst: str) -> None:
        """PortTap kancası: ARP zehirleme ve ARP süpürme kontrolü (sadece `full` profilde)."""
        if self._profile != "full":
            return
        conn = self._conn()
        owner = conn.execute("SELECT mac FROM devices WHERE ip=? AND status='approved'",
                             (psrc,)).fetchone()
        reason = spoof_reason(hwsrc, psrc, owner["mac"] if owner else None)
        if reason:
            self._alert(conn, ether_src, self._known_ip(conn, ether_src), "arp_spoofing", reason)
            return
        self._scan_event(conn, "arp", ts, ether_src, psrc, pdst)

    def on_syn(self, ts: float, ether_src: str, src_ip: str, dst_ip: str, dport: int) -> None:
        """PortTap kancası: port taraması kontrolü (sadece `full` profilde)."""
        if self._profile == "full":
            self._scan_event(self._conn(), "syn", ts, ether_src, src_ip, f"{dst_ip}:{dport}")

    def _scan_event(self, conn: sqlite3.Connection, kind: str, ts: float, mac: str,
                    ip: str, target: str) -> None:
        row = conn.execute("SELECT device_type FROM devices WHERE mac=?", (mac,)).fetchone()
        if row is not None and row["device_type"] == "infrastructure":
            return   # router tüm cihazlar için ARP sorar; tarama değildir
        reason = self._scan.add(kind, ts, mac, target)
        if reason:
            self._alert(conn, mac, ip if ip != "0.0.0.0" else self._known_ip(conn, mac),
                        "abnormal_scan", reason)

    @staticmethod
    def _known_ip(conn: sqlite3.Connection, mac: str) -> str | None:
        row = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
        return row["ip"] if row else None

    def _move_ip(self, conn: sqlite3.Connection, row: sqlite3.Row, new_ip: str) -> None:
        suspect = conn.execute("SELECT 1 FROM alerts WHERE mac=? AND type='impersonation' "
                               "AND ts > ?", (row["mac"], self._clock() - self._cooldown)).fetchone()
        if suspect:
            log.warning("%s için IP %s onaylanmadı: yakın zamanda impersonation alarmı var",
                        row["mac"], new_ip)
            return
        # Aynı IP daha önce başka cihazdaysa (kira yeniden dağıtıldı) eski bağı temizle;
        # yoksa ARP koruması yeni sahibini zehirleyici sanar.
        conn.execute("UPDATE devices SET ip=NULL WHERE ip=? AND mac!=?", (new_ip, row["mac"]))
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
        cur = conn.execute("INSERT INTO alerts (ts, mac, ip, type, severity, attack_id, action, "
                           "reason, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (now, mac, ip, atype, attack.severity, attack.attack_id,
                            attack.action, reason, now))
        log.warning("ALARM %s %s %s: %s", atype, mac, ip, reason)
        if self._on_alert:
            self._on_alert(conn, cur.lastrowid)
