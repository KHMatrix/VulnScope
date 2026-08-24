"""
KHMatrix - Database Layer
All queries are parameterized. No string concatenation of untrusted input.
"""
import sqlite3
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "khmatrix.db")

_local = threading.local()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,          -- ip, cidr, hostname, domain, url
    device_type_hint TEXT,              -- optional operator hint: router, camera, etc.
    owner TEXT,
    environment TEXT,
    notes TEXT,
    authorized INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL,            -- single, continuous
    status TEXT NOT NULL,               -- running, completed, aborted, failed
    started_at TEXT NOT NULL,
    finished_at TEXT,
    summary_json TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    confidence TEXT,
    os_indicator TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    banner TEXT
);

CREATE TABLE IF NOT EXISTS websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT,
    status_code INTEGER,
    headers_json TEXT,
    tls_json TEXT,
    cookies_json TEXT,
    technologies_json TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    url TEXT,
    status INTEGER,
    content_type TEXT,
    size INTEGER,
    response_time REAL,
    redirect TEXT,
    auth_indicator TEXT,
    relevance TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    finding_ref TEXT,
    title TEXT,
    severity TEXT,
    confidence TEXT,
    host_ip TEXT,
    hostname TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    url TEXT,
    description TEXT,
    evidence TEXT,
    security_impact TEXT,
    attacker_impact TEXT,
    cve TEXT,
    cwe TEXT,
    cvss REAL,
    affected_versions TEXT,
    remediation_immediate TEXT,
    remediation_permanent TEXT,
    verification TEXT,
    refs TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS monitoring_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    change_type TEXT,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_websites_scan ON websites(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_site ON endpoints(website_id);
"""


def get_conn():
    """Thread-local SQLite connection."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


@contextmanager
def cursor():
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()


def now():
    return datetime.utcnow().isoformat() + "Z"


def dict_rows(rows):
    return [dict(r) for r in rows]


# ---------- Users ----------
def create_user(username, password_hash):
    with cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
            (username, password_hash, now()),
        )
        return cur.lastrowid


def get_user(username):
    with cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None


def any_user_exists():
    with cursor() as cur:
        cur.execute("SELECT COUNT(*) AS c FROM users")
        return cur.fetchone()["c"] > 0


# ---------- Assets ----------
def add_asset(name, target, target_type, device_type_hint, owner, environment, notes, authorized):
    with cursor() as cur:
        cur.execute(
            """INSERT INTO assets (name, target, target_type, device_type_hint, owner, environment,
               notes, authorized, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (name, target, target_type, device_type_hint, owner, environment, notes,
             1 if authorized else 0, now()),
        )
        return cur.lastrowid


def list_assets():
    with cursor() as cur:
        cur.execute("SELECT * FROM assets ORDER BY created_at DESC")
        return dict_rows(cur.fetchall())


def get_asset(asset_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def delete_asset(asset_id):
    with cursor() as cur:
        cur.execute("DELETE FROM assets WHERE id = ?", (asset_id,))


# ---------- Scans ----------
def create_scan(asset_id, scan_type):
    with cursor() as cur:
        cur.execute(
            "INSERT INTO scans (asset_id, scan_type, status, started_at) VALUES (?,?,?,?)",
            (asset_id, scan_type, "running", now()),
        )
        return cur.lastrowid


def finish_scan(scan_id, status, summary):
    with cursor() as cur:
        cur.execute(
            "UPDATE scans SET status=?, finished_at=?, summary_json=? WHERE id=?",
            (status, now(), json.dumps(summary), scan_id),
        )


def get_scan(scan_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_scans(asset_id=None):
    with cursor() as cur:
        if asset_id:
            cur.execute("SELECT * FROM scans WHERE asset_id=? ORDER BY started_at DESC", (asset_id,))
        else:
            cur.execute("SELECT * FROM scans ORDER BY started_at DESC")
        return dict_rows(cur.fetchall())


def previous_scan(asset_id, before_scan_id):
    with cursor() as cur:
        cur.execute(
            """SELECT * FROM scans WHERE asset_id=? AND id != ? AND status='completed'
               ORDER BY started_at DESC LIMIT 1""",
            (asset_id, before_scan_id),
        )
        row = cur.fetchone()
        return dict(row) if row else None


# ---------- Hosts / Services ----------
def add_host(scan_id, asset_id, ip, mac, hostname, vendor, device_type, confidence, os_indicator):
    with cursor() as cur:
        cur.execute(
            """INSERT INTO hosts (scan_id, asset_id, ip, mac, hostname, vendor, device_type,
               confidence, os_indicator, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, asset_id, ip, mac, hostname, vendor, device_type, confidence, os_indicator, now()),
        )
        return cur.lastrowid


def add_service(host_id, port, protocol, state, service, product, version, banner):
    with cursor() as cur:
        cur.execute(
            """INSERT INTO services (host_id, port, protocol, state, service, product, version, banner)
               VALUES (?,?,?,?,?,?,?,?)""",
            (host_id, port, protocol, state, service, product, version, banner),
        )
        return cur.lastrowid


def hosts_for_scan(scan_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM hosts WHERE scan_id=?", (scan_id,))
        hosts = dict_rows(cur.fetchall())
        for h in hosts:
            cur.execute("SELECT * FROM services WHERE host_id=?", (h["id"],))
            h["services"] = dict_rows(cur.fetchall())
        return hosts


# ---------- Websites / Endpoints ----------
def add_website(scan_id, asset_id, url, status_code, headers, tls, cookies, technologies):
    with cursor() as cur:
        cur.execute(
            """INSERT INTO websites (scan_id, asset_id, url, status_code, headers_json, tls_json,
               cookies_json, technologies_json) VALUES (?,?,?,?,?,?,?,?)""",
            (scan_id, asset_id, url, status_code, json.dumps(headers), json.dumps(tls),
             json.dumps(cookies), json.dumps(technologies)),
        )
        return cur.lastrowid


def add_endpoint(website_id, url, status, content_type, size, response_time, redirect, auth_indicator, relevance):
    with cursor() as cur:
        cur.execute(
            """INSERT INTO endpoints (website_id, url, status, content_type, size, response_time,
               redirect, auth_indicator, relevance) VALUES (?,?,?,?,?,?,?,?,?)""",
            (website_id, url, status, content_type, size, response_time, redirect, auth_indicator, relevance),
        )


def websites_for_scan(scan_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM websites WHERE scan_id=?", (scan_id,))
        sites = dict_rows(cur.fetchall())
        for s in sites:
            s["headers"] = json.loads(s.pop("headers_json") or "{}")
            s["tls"] = json.loads(s.pop("tls_json") or "{}")
            s["cookies"] = json.loads(s.pop("cookies_json") or "[]")
            s["technologies"] = json.loads(s.pop("technologies_json") or "[]")
            cur.execute("SELECT * FROM endpoints WHERE website_id=?", (s["id"],))
            s["endpoints"] = dict_rows(cur.fetchall())
        return sites


# ---------- Findings ----------
def add_finding(f: dict):
    with cursor() as cur:
        cur.execute(
            """INSERT INTO findings (scan_id, asset_id, finding_ref, title, severity, confidence,
               host_ip, hostname, port, protocol, service, product, version, url, description,
               evidence, security_impact, attacker_impact, cve, cwe, cvss, affected_versions,
               remediation_immediate, remediation_permanent, verification, refs, first_seen,
               last_seen, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f["scan_id"], f["asset_id"], f.get("finding_ref"), f.get("title"), f.get("severity"),
                f.get("confidence"), f.get("host_ip"), f.get("hostname"), f.get("port"), f.get("protocol"),
                f.get("service"), f.get("product"), f.get("version"), f.get("url"), f.get("description"),
                f.get("evidence"), f.get("security_impact"), f.get("attacker_impact"), f.get("cve"),
                f.get("cwe"), f.get("cvss"), f.get("affected_versions"), f.get("remediation_immediate"),
                f.get("remediation_permanent"), f.get("verification"), f.get("refs"),
                f.get("first_seen", now()), f.get("last_seen", now()), f.get("status", "open"),
            ),
        )
        return cur.lastrowid


def findings_for_scan(scan_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))
        return dict_rows(cur.fetchall())


def findings_for_asset(asset_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM findings WHERE asset_id=? ORDER BY last_seen DESC", (asset_id,))
        return dict_rows(cur.fetchall())


# ---------- Monitoring changes ----------
def add_change(asset_id, scan_id, change_type, description):
    with cursor() as cur:
        cur.execute(
            "INSERT INTO monitoring_changes (asset_id, scan_id, change_type, description, created_at) VALUES (?,?,?,?,?)",
            (asset_id, scan_id, change_type, description, now()),
        )


def changes_for_asset(asset_id):
    with cursor() as cur:
        cur.execute("SELECT * FROM monitoring_changes WHERE asset_id=? ORDER BY created_at DESC", (asset_id,))
        return dict_rows(cur.fetchall())
