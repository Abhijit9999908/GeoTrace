import sqlite3
import json
from datetime import datetime

DB_PATH = "geotrace.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database and create tables if they don't exist."""
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                domain    TEXT NOT NULL,
                ip        TEXT,
                country   TEXT,
                region    TEXT,
                city      TEXT,
                lat       REAL,
                lon       REAL,
                isp       TEXT,
                org       TEXT,
                threat_level  TEXT,
                threat_score  INTEGER,
                threat_reasons TEXT,
                scanned_at    TEXT DEFAULT (datetime('now'))
            )
        """)
        # Migration: add missing columns to old DBs
        existing = {r[1] for r in conn.execute("PRAGMA table_info(scan_history)")}
        for col, typedef in [
            ("region", "TEXT"),
            ("city", "TEXT"),
            ("isp", "TEXT"),
            ("org", "TEXT"),
            ("threat_score", "INTEGER"),
            ("threat_reasons", "TEXT"),
        ]:
            if col not in existing:
                conn.execute(f"ALTER TABLE scan_history ADD COLUMN {col} {typedef}")
        conn.commit()


def save_result(result: dict):
    """Save a scan result to the database."""
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO scan_history
                (domain, ip, country, region, city, lat, lon, isp, org,
                 threat_level, threat_score, threat_reasons, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("domain"),
            result.get("ip"),
            result.get("country"),
            result.get("region"),
            result.get("city"),
            result.get("lat"),
            result.get("lon"),
            result.get("isp"),
            result.get("org"),
            result.get("threat_level"),
            result.get("threat_score"),
            json.dumps(result.get("threat_reasons", [])),
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        conn.commit()


def get_history(limit: int = 50) -> list:
    """Retrieve recent scan history."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        try:
            d["threat_reasons"] = json.loads(d.get("threat_reasons") or "[]")
        except (json.JSONDecodeError, TypeError):
            d["threat_reasons"] = []
        results.append(d)
    return results


def clear_all():
    """Delete all scan history records."""
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
            
