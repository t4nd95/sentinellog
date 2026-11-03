import hashlib
import json
from datetime import datetime, timezone

import streamlit as st

from database import connect_db


STATUSES = ["Açık", "İnceleniyor", "Kapalı"]
SEVERITIES = ["Düşük", "Orta", "Yüksek", "Kritik"]


def alarm_id(alarm):
    evidence = (
        alarm["Kanıt"]
        .fillna("")
        .astype(str)
        .to_dict(orient="records")
    )
    identity = {
        "rule": alarm["Kural"],
        "source": alarm["Kaynak"],
        "host": alarm["Sunucu"],
        "ip": alarm["IP"],
        "time": str(alarm["Zaman"]),
        "evidence": evidence,
    }
    content = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def init_alarm_management():
    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alarm_management (
                alarm_id TEXT PRIMARY KEY,
                rule_name TEXT NOT NULL,
                host TEXT NOT NULL,
                ip TEXT NOT NULL,
                alarm_time TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                note TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)


def render_alarm_management(alerts):
    init_alarm_management()
    st.divider()
    st.subheader("Alarm Yönetimi")

    if not alerts:
        st.info("Yönetilecek alarm bulunamadı.")
        return

    alarms = {alarm_id(alarm): alarm for alarm in alerts}

    selected_id = st.selectbox(
        "Düzenlenecek alarm",
        list(alarms),
        format_func=lambda key: (
            f"{alarms[key]['Kural']} | "
            f"{alarms[key]['Sunucu']} | "
            f"{alarms[key]['IP']} | "
            f"{alarms[key]['Zaman']}"
        ),
        key="managed_alarm_selection",
    )
    alarm = alarms[selected_id]

    with connect_db() as connection:
        saved = connection.execute("""
            SELECT status, severity, note, updated_at
            FROM alarm_management
            WHERE alarm_id = ?
        """, (selected_id,)).fetchone()

    status, severity, note = (
        saved[:3] if saved else ("Açık", "Orta", "")
    )

    st.caption(
        "Önem seviyesi analist tarafından atanır. "
        "Kaydet düğmesine basıldığında veritabanına yazılır."
    )

    with st.form(key=f"alarm_form_{selected_id}"):
        left, right = st.columns(2)

        new_status = left.selectbox(
            "İnceleme durumu",
            STATUSES,
            index=STATUSES.index(status),
            key=f"status_{selected_id}",
        )
        new_severity = right.selectbox(
            "Önem seviyesi",
            SEVERITIES,
            index=SEVERITIES.index(severity),
            key=f"severity_{selected_id}",
        )
        new_note = st.text_area(
            "İnceleme notu",
            value=note,
            max_chars=5000,
            key=f"note_{selected_id}",
        )
        submitted = st.form_submit_button("Değişiklikleri Kaydet")

    if submitted:
        updated_at = datetime.now(timezone.utc).isoformat()

        with connect_db() as connection:
            connection.execute("""
                INSERT INTO alarm_management (
                    alarm_id, rule_name, host, ip, alarm_time,
                    status, severity, note, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alarm_id) DO UPDATE SET
                    status = excluded.status,
                    severity = excluded.severity,
                    note = excluded.note,
                    updated_at = excluded.updated_at
            """, (
                selected_id,
                alarm["Kural"],
                alarm["Sunucu"],
                alarm["IP"],
                str(alarm["Zaman"]),
                new_status,
                new_severity,
                new_note,
                updated_at,
            ))

        st.success("Alarm durumu, önem seviyesi ve not kaydedildi.")

    elif saved:
        st.caption(f"Son kayıt (UTC): {saved[3]}")

    st.caption(
        "Kapalı durumu incelemenin tamamlandığını belirtir; "
        "alarmı veya kanıtları silmez."
    )