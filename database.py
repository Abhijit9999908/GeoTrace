"""
database.py — SQLite database helper for GeoTrace

Handles creating the database table and inserting/reading analysis records.
Uses Python's built-in sqlite3 module (no extra install needed).
"""

import sqlite3
import os

# Path to the SQLite database file (created automatically in the project folder)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geotrace.db")


def get_connection():
    """
    Open a connection to the SQLite database.
    Returns a connection object.
    """
    conn = sqlite3.connect(DB_PATH)
    # Return rows as dictionaries instead of tuples (easier to work with)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create the 'analyses' table if it doesn't already exist.
    Called once when the app starts.
    """
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
    """
    Insert a new analysis record into the database.

    Parameters:
        domain       – the domain name entered by the user
        ip_address   – resolved IP address
        country      – country name from geolocation
        latitude     – geographic latitude
        longitude    – geographic longitude
        threat_level – SAFE, TRACKER, or UNKNOWN
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analyses (domain, ip_address, country, latitude, longitude, threat_level)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (domain, ip_address, country, latitude, longitude, threat_level))

    conn.commit()
    conn.close()


def get_history():
    """
    Retrieve all past analyses, newest first.
    Returns a list of dictionaries.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses ORDER BY id DESC")
    rows = cursor.fetchall()

    # Convert sqlite3.Row objects to plain dictionaries
    history = [dict(row) for row in rows]

    conn.close()
    return history
