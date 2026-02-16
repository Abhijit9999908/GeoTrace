"""
database.py — SQLite database helper
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geotrace.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT    NOT NULL,
            ip_address  TEXT    NOT NULL,
            country     TEXT    NOT NULL,
            latitude    REAL    NOT NULL,
            longitude   REAL    NOT NULL,
            threat_level TEXT   NOT NULL,
            timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()

def save_analysis(domain, ip_address, country, latitude, longitude, threat_level):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analyses (domain, ip_address, country, latitude, longitude, threat_level)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (domain, ip_address, country, latitude, longitude, threat_level))
    conn.commit()
    conn.close()

def get_history():
    """Retrieve all past analyses."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses ORDER BY id DESC")
    rows = cursor.fetchall()
    history = [dict(row) for row in rows]
    conn.close()
    return history
