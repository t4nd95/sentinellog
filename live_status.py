
from datetime import datetime, timezone
import streamlit as st
from database import connect_db


def init_status():
    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS collector_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                last_success TEXT,
                error TEXT NOT NULL
            )
        """)


def write_status(state, error=""):
    init_status()
    now = datetime.now(timezone.utc).isoformat()
    success = now if state == "running" else None

    with connect_db() as connection:
        connection.execute("""
            INSERT INTO collector_status (
                id, state, checked_at, last_success, error
            ) VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                state = excluded.state,
                checked_at = excluded.checked_at,
                last_success = COALESCE(
                    excluded.last_success,
                    collector_status.last_success
                ),
                error = excluded.error
        """, (state, now, success, str(error)))


def render_collector_status():
    init_status()

    with connect_db() as connection:
        row = connection.execute("""
            SELECT state, checked_at, last_success, error
            FROM collector_status WHERE id = 1
        """).fetchone()

    if row is None:
        st.sidebar.caption("Canlı log toplama: henüz durum alınmadı")
        return

    state, checked_at, last_success, error = row
    age = (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(checked_at)
    ).total_seconds()

    if state == "stopped":
        st.sidebar.caption("Canlı log toplama: durduruldu")
    elif not 0 <= age <= 45:
        st.sidebar.warning("Toplayıcıdan güncel durum alınamıyor.")
    elif state == "error":
        st.sidebar.error("Canlı log toplama: hata")
    else:
        st.sidebar.success("Canlı log toplama: aktif")

    if last_success:
        stamp = datetime.fromisoformat(last_success)
        st.sidebar.caption(
            "Son başarılı kontrol (UTC): "
            + stamp.strftime("%d.%m.%Y %H:%M:%S")
        )

    if error:
        with st.sidebar.expander("Son toplama hatası"):
            st.write(error)
