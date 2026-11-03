import hashlib
import json
import sqlite3
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "sentinellog.db"

COLUMNS = [
    "Zaman", "Kaynak", "Sunucu", "Event ID",
    "IP", "Kullanıcı", "Sonuç", "Ham Log",
]


def connect_db():
    # Each browser session has an independent temporary database.
    import streamlit as st
    import tempfile
    if "_session_db_directory" not in st.session_state:
        st.session_state["_session_db_directory"] = tempfile.TemporaryDirectory(
            prefix="sentinellog_session_"
        )
    path = Path(st.session_state["_session_db_directory"].name) / "events.db"
    return sqlite3.connect(str(path), timeout=30)


def init_db():

    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                event_time TEXT NOT NULL,
                source TEXT NOT NULL,
                host TEXT NOT NULL,
                event_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                result TEXT NOT NULL,
                raw_log TEXT NOT NULL
            )
        """)


def save_events(events):
    records = []

    for row in events[COLUMNS].fillna("").itertuples(
        index=False, name=None
    ):
        values = tuple(str(value) for value in row)
        fingerprint = hashlib.sha256(
            json.dumps(values, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        records.append((fingerprint, *values))

    with connect_db() as connection:
        before = connection.total_changes

        connection.executemany("""
            INSERT INTO events (
                fingerprint, event_time, source, host, event_id,
                ip, username, result, raw_log
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO NOTHING
        """, records)

        added = connection.total_changes - before

    return added, len(records) - added


def load_events():
    with connect_db() as connection:
        rows = connection.execute("""
            SELECT event_time, source, host, event_id,
                   ip, username, result, raw_log
            FROM events
            ORDER BY event_time DESC, id DESC
        """).fetchall()

    return pd.DataFrame(rows, columns=COLUMNS)