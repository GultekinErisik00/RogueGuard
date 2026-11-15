"""SQLite (WAL modu) veritabanı: devices, observations, events, alerts, approvals.

Daemon ve Streamlit aynı dosyayı kullanır. Dashboard sadece `approvals`'a yazar,
daemon onu okuyup kararı uygular; iki süreç arasında başka iletişim katmanı yok.
"""
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    dhcp_fp TEXT,            -- JSON: option 55 listesi, vendor class, client id
    ports TEXT,              -- JSON: [{port, service, banner}]
    mdns TEXT,               -- JSON: servis türleri listesi
    destinations TEXT,       -- JSON: "ip:port" listesi
    publish_interval REAL,   -- saniye (MQTT yayınları arası medyan)
    device_type TEXT,        -- kural tabanlı tür (LLM tahmini karar motoruna girmez)
    status TEXT NOT NULL DEFAULT 'pending',   -- approved | pending | blocked | quarantined
    first_seen REAL,
    last_seen REAL
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT,
    source TEXT NOT NULL,    -- arp | dhcp | mdns | nmap | traffic
    data TEXT NOT NULL       -- ham veri (JSON)
);
CREATE INDEX IF NOT EXISTS obs_mac_src ON observations (mac, source, ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    mac TEXT NOT NULL,
    type TEXT NOT NULL,      -- new_device | changed_device
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    attack_id TEXT,
    action TEXT,
    reason TEXT,
    detected_at REAL,
    contained_at REAL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    mac TEXT NOT NULL,
    decision TEXT NOT NULL,  -- approve | reject
    applied_at REAL          -- daemon uyguladığında doldurur
);
"""


def connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    return conn


def add_observation(conn: sqlite3.Connection, mac: str, ip: str | None,
                    source: str, data: dict[str, Any], ts: float | None = None) -> None:
    conn.execute("INSERT INTO observations (ts, mac, ip, source, data) VALUES (?, ?, ?, ?, ?)",
                 (ts or time.time(), mac, ip, source, json.dumps(data, sort_keys=True)))


def add_event(conn: sqlite3.Connection, mac: str, etype: str, data: dict[str, Any]) -> None:
    conn.execute("INSERT INTO events (ts, mac, type, data) VALUES (?, ?, ?, ?)",
                 (time.time(), mac, etype, json.dumps(data, sort_keys=True)))


def known_macs(conn: sqlite3.Connection) -> set[str]:
    """Daha önce görülmüş tüm MAC'ler (yeniden başlatmada new_device tekrar üretilmesin)."""
    rows = conn.execute("SELECT mac FROM devices UNION SELECT DISTINCT mac FROM observations")
    return {r["mac"] for r in rows}
