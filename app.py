import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from database import init_db, load_events, save_events
from parsers import parse_windows, parse_ssh
from rules import detect_alerts

st.set_page_config(
    page_title="SentinelLog | Operations Console",
    page_icon="🛡️",
    layout="wide",
)


# SENTINELLOG_AUTO_REFRESH
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

if st.sidebar.checkbox(
    "Otomatik yenile (5 saniye)",
    value=False,
    key="auto_refresh_enabled",
):
    st_autorefresh(interval=5000, key="sentinellog_refresh_timer")

st.sidebar.caption(
    "Ekran güncellemesi: " + datetime.now().strftime("%H:%M:%S")
)


BASE_DIR = Path(__file__).resolve().parent
COLORS = {"Başarılı": "#52c9ac", "Başarısız": "#fa795f"}

RULE_INFO = [
    {
        "Kural": "Tekrarlanan başarısız giriş",
        "Durum": "Aktif",
        "Açıklama": "Aynı IP, sunucu ve kaynak için başarısız girişler.",
    },
    {
        "Kural": "Çok kullanıcıya giriş denemesi",
        "Durum": "Aktif",
        "Açıklama": "Aynı IP, sunucu ve kaynakta farklı hesaplara denemeler.",
    },
    {
        "Kural": "Başarısızlık sonrası başarılı giriş",
        "Durum": "Aktif",
        "Açıklama": "Aynı kullanıcı/IP/sunucu/kaynakta hatalardan sonra başarı.",
    },
    {
        "Kural": "Yetkili hesap takibi",
        "Durum": "Planlandı",
        "Açıklama": "Tanımlı yönetici hesaplarının girişleri.",
    },
    {
        "Kural": "Davranış anomalisi",
        "Durum": "Planlandı",
        "Açıklama": "Yeterli veri ve değerlendirme gerekli.",
    },
]

st.markdown("""
<style>
.stApp {background:#10161d;color:#dce5ee;}
.block-container {
    padding-top:1.4rem;padding-bottom:2rem;max-width:1900px;
}
h1,h2,h3 {color:#edf3f8!important;}
h1 {font-size:25px!important;letter-spacing:-.6px;}
h3 {font-size:15px!important;font-weight:600!important;}
[data-testid="stSidebar"] {
    background:#111c2a;border-right:1px solid #2a394c;
}
[data-testid="stSidebar"] h1 {font-size:24px!important;}
[data-testid="stSidebar"] [role="radiogroup"] {gap:6px;}
[data-testid="stSidebar"] [role="radiogroup"] > label {
    width:100%;padding:11px 13px!important;
    margin:0!important;border-radius:7px;
    border:1px solid transparent;box-sizing:border-box;
}
[data-testid="stSidebar"] [role="radiogroup"] > label:hover {
    background:#203147;border-color:#344c67;
}
[data-testid="stSidebar"] [role="radiogroup"] > label > div:first-child {
    display:none;
}
[data-testid="stSidebar"] [role="radiogroup"] > label p {
    color:#bac9db;font-size:14px;
}
[data-testid="stSidebar"] [role="radiogroup"] > label:has(input:checked) {
    background:#193c43;border-color:#32666b;
    box-shadow:inset 3px 0 #64dec0;
}
[data-testid="stSidebar"] [role="radiogroup"] > label:has(input:checked) p {
    color:#8bead2;font-weight:600;
}
[data-testid="stSidebar"] [role="radiogroup"] > label:focus-within {
    outline:2px solid #64dec0;
}
[data-testid="stMetric"] {
    background:#19232f;border:1px solid #2e4053;
    border-top:2px solid #52c9ac;border-radius:7px;padding:15px;
}
[data-testid="stMetricLabel"] {color:#a9bbce;}
[data-testid="stMetricValue"] {color:#f3f6fa;font-size:29px;}
[data-testid="stVerticalBlockBorderWrapper"] {
    border-color:#2e4053!important;border-radius:7px!important;
}
.stButton>button,.stDownloadButton>button {
    border-radius:6px;border:1px solid #39566c;
}
.topbar {
    display:flex;justify-content:space-between;
    gap:12px;flex-wrap:wrap;padding-bottom:16px;
    border-bottom:1px solid #2a394b;margin-bottom:20px;
}
.brand {font-size:24px;font-weight:700;color:#f1f5f9;}
.brand span {color:#63daba;}
.topmeta {
    font-size:11px;letter-spacing:1px;
    color:#9cafc5;padding-top:8px;
}
</style>
""", unsafe_allow_html=True)


def plot(figure, height=260):
    figure.update_layout(
        template="plotly_dark",
        paper_bgcolor="#18222d",
        plot_bgcolor="#18222d",
        font=dict(color="#cedae6", size=11),
        margin=dict(l=12, r=12, t=15, b=12),
        height=height,
        legend_title_text="",
    )
    st.plotly_chart(figure, width="stretch")


def ranking(series, title):
    st.subheader(title)
    counts = series.value_counts().head(6)

    if counts.empty:
        st.caption("Gösterilecek kayıt yok.")
        return

    data = counts.rename_axis("Kaynak").reset_index(name="Olay")
    figure = px.bar(
        data,
        x="Olay",
        y="Kaynak",
        orientation="h",
        color_discrete_sequence=["#f58258"],
    )
    figure.update_yaxes(autorange="reversed", title=None)
    plot(figure, 210)


def save_import(frame, skipped, filename):
    added, duplicates = save_events(frame)
    st.session_state.import_message = (
        f"{filename} · {added} yeni kayıt · "
        f"{duplicates} tekrar · {skipped} atlanan"
    )


def upload_page():
    st.caption("Windows Security ve Linux SSH giriş kayıtlarını ekleyin.")
    left, right = st.columns([2, 1])

    with left:
        with st.container(border=True):
            st.subheader("Log İçe Aktarma")

            kind = st.selectbox(
                "Dosya türü",
                ["Windows EVTX", "Linux SSH"],
            )
            year, timezone = 2026, "UTC"

            if kind == "Linux SSH":
                year = int(st.number_input(
                    "Yıl bulunmayan kayıtların yılı",
                    min_value=2000,
                    max_value=2100,
                    value=2026,
                ))
                timezone = st.selectbox(
                    "Saat dilimi bulunmayan kayıtların saat dilimi",
                    ["UTC", "Europe/Istanbul"],
                )
                st.caption(
                    "Eksik yıl ve saat dilimi bu değerlerle tamamlanır. "
                    "Yılsız dosya tek bir yıla ait olmalı."
                )

            uploaded = st.file_uploader(
                "Dosya seç",
                type=["evtx"] if kind == "Windows EVTX" else ["log", "txt"],
                key=f"upload_{kind}",
            )

            if st.button(
                "Dosyayı Oku ve Kaydet",
                disabled=uploaded is None,
            ):
                st.session_state.pop("import_message", None)

                try:
                    if uploaded.size > 10 * 1024 * 1024:
                        raise ValueError("En fazla 10 MB dosya yükleyebilirsiniz.")
                    with st.spinner("Loglar işleniyor..."):
                        if kind == "Windows EVTX":
                            path = None

                            try:
                                with tempfile.NamedTemporaryFile(
                                    suffix=".evtx",
                                    delete=False,
                                ) as temporary:
                                    temporary.write(uploaded.getvalue())
                                    path = Path(temporary.name)

                                frame, skipped = parse_windows(path)

                            finally:
                                if path is not None:
                                    path.unlink(missing_ok=True)

                        else:
                            frame, skipped = parse_ssh(
                                uploaded.getvalue().decode("utf-8-sig"),
                                year,
                                timezone,
                            )

                        save_import(frame, skipped, uploaded.name)

                    st.rerun()

                except Exception as error:
                    st.error(f"Dosya işlenemedi: {error}")

            from sample_data import sample_ssh
            st.caption("İsteğe bağlı örnekler sentetiktir; gerçek saldırı veya canlı kayıt değildir.")
            if st.button("Sentetik Örnek Logları Yükle"):
                frame, skipped = parse_ssh(sample_ssh(), 2026, "UTC")
                save_import(frame, skipped, "Sentetik SSH örnekleri")
                st.rerun()

            if st.session_state.get("import_message"):
                st.success(st.session_state.import_message)

    with right:
        with st.container(border=True):
            st.subheader("Desteklenen Kaynaklar")
            st.write("**Windows:** Security 4624 / 4625")
            st.write("**Linux:** SSH password / publickey giriş sonuçları")
            st.caption("Diğer kayıt türleri atlanır.")
            st.write("**Depolama:** SQLite")
            st.caption(
                "Yeni kayıtlar eklenir. Aynı kayıt tekrar eklenmez."
            )


try:
    init_db()
    all_events = load_events()

except Exception as error:
    st.error(f"Veritabanı açılamadı: {error}")
    st.stop()

st.sidebar.title("🛡️ SentinelLog")
st.sidebar.caption("OPERATIONS CONSOLE")

page = st.sidebar.radio(
    "Çalışma Alanı",
    [
        "SIEM Dashboard",
        "Performans İzleme",
        "Olay İnceleme",
        "Alarm Merkezi",
        "Veri Kaynakları",
        "Raporlar",
        "Tespit Kuralları",
    ],
)

st.sidebar.divider()

with st.sidebar.expander("Tespit Ayarları"):
    threshold = int(st.number_input(
        "Başarısız giriş / farklı kullanıcı eşiği",
        min_value=2,
        max_value=100,
        value=5,
    ))
    minutes = int(st.number_input(
        "Pencere (dakika)",
        min_value=1,
        max_value=60,
        value=5,
    ))
    st.caption(
        "Çok kullanıcı kuralında eşik, farklı kullanıcı sayısıdır. "
        "Diğer iki kuralda başarısız giriş sayısıdır."
    )

st.sidebar.caption("● Oturuma özel SQLite")
from live_status import render_collector_status
st.sidebar.caption("Canlı Windows bağlantısı: henüz kurulmadı")

st.markdown("""
<div class="topbar">
    <div class="brand">Sentinel<span>Log</span></div>
    <div class="topmeta">SECURITY & SYSTEM OPERATIONS</div>
</div>
""", unsafe_allow_html=True)

st.title(page)
st.info(
    "Bulut sunum sürümü · Windows bilgisayarınıza canlı bağlantı henüz yok. "
    "Dosya yükleyerek gerçek logları analiz edebilirsiniz. "
    "Yüklemeler ve alarm notları yalnızca bu tarayıcı oturumuna aittir; "
    "yeniden bağlantı veya sunucu yeniden başlatılınca kaybolabilir."
)

if page == "Veri Kaynakları":
    upload_page()
    st.stop()

if page == "Performans İzleme":
    from performance import render_performance
    render_performance()
    st.stop()

if page == "Tespit Kuralları":
    st.dataframe(
        pd.DataFrame(RULE_INFO),
        width="stretch",
        hide_index=True,
    )
    st.caption(
        f"Geçerli eşik: {threshold} · Pencere: {minutes} dakika."
    )
    st.caption(
        "İlk iki kural her kaynak/sunucu/IP için ilk eşik aşımını; "
        "üçüncü kural ayrıca kullanıcı bazında ilk eşleşmeyi gösterir."
    )
    st.stop()

# SIEM sayfaları için ortak filtreler.
filters = st.columns(3)

source = filters[0].selectbox(
    "Kaynak",
    ["Tümü"] + sorted(all_events["Kaynak"].unique().tolist()),
)
host = filters[1].selectbox(
    "Sunucu",
    ["Tümü"] + sorted(all_events["Sunucu"].unique().tolist()),
)
period = filters[2].selectbox(
    "Tarih",
    ["Tüm kayıtlar", "Özel aralık"],
)

events = all_events.copy()

if source != "Tümü":
    events = events[events["Kaynak"] == source]

if host != "Tümü":
    events = events[events["Sunucu"] == host]

if period == "Özel aralık":
    timestamps = pd.to_datetime(
        events["Zaman"],
        utc=True,
        errors="coerce",
    )
    valid = timestamps.dropna()

    if not valid.empty:
        dates = st.date_input(
            "UTC tarih aralığı",
            value=(valid.min().date(), valid.max().date()),
        )

        if len(dates) != 2:
            st.info("Başlangıç ve bitiş tarihlerini seçin.")
            st.stop()

        start = pd.Timestamp(dates[0], tz="UTC")
        end = pd.Timestamp(dates[1], tz="UTC") + pd.Timedelta(days=1)

        events = events[
            (timestamps >= start) & (timestamps < end)
        ]

events = events.reset_index(drop=True)
alerts = detect_alerts(events, threshold, minutes)
failures = events[events["Sonuç"] == "Başarısız"]

alarm_table = pd.DataFrame([
    {
        "Kural": alarm["Kural"],
        "Zaman (UTC)": str(alarm["Zaman"]),
        "Kaynak": alarm["Kaynak"],
        "Sunucu": alarm["Sunucu"],
        "IP": alarm["IP"],
        "Kanıt": alarm["Sayı"],
    }
    for alarm in alerts
], columns=[
    "Kural", "Zaman (UTC)", "Kaynak", "Sunucu", "IP", "Kanıt",
])

st.caption(
    f"{len(events)} filtrelenmiş / {len(all_events)} toplam olay · "
    "UTC · İçe aktarılan kayıtlar; canlı bağlantı değil."
)

if page == "SIEM Dashboard":
    cards = st.columns(5)
    cards[0].metric("GİRİŞ OLAYI", len(events))
    cards[1].metric("BAŞARISIZ", len(failures))
    cards[2].metric("ALARM", len(alerts))
    cards[3].metric("SUNUCU", events["Sunucu"].nunique())
    cards[4].metric(
        "FARKLI IP",
        events.loc[events["IP"] != "Yok", "IP"].nunique(),
    )
    st.write("")

    left, right = st.columns([1, 2.1])

    with left:
        with st.container(border=True):
            ranking(
                events["Sunucu"],
                "En Çok Olay Üreten Sunucular",
            )

        with st.container(border=True):
            ranking(
                failures["Sunucu"],
                "Başarısız Giriş Görülen Sunucular",
            )

    with right:
        with st.container(border=True):
            st.subheader("IP Konum Haritası")

            world = go.Figure(go.Scattergeo(
                lon=[],
                lat=[],
                mode="markers",
                marker=dict(color="#fa795f", size=10),
            ))
            world.update_geos(
                projection_type="natural earth",
                showland=True,
                landcolor="#cbd5df",
                showocean=True,
                oceancolor="#18222d",
                showcountries=True,
                countrycolor="#8b9aab",
                showcoastlines=False,
                showframe=False,
                bgcolor="#18222d",
            )
            plot(world, 420)

            st.caption(
                "Konum verisi henüz bağlı değil. "
                "IP konumu, kullanıcının kesin konumu değildir."
            )

    first, second, third = st.columns([1.35, 1, 1])

    with first:
        with st.container(border=True):
            st.subheader("Olay Zaman Çizelgesi")

            timed = events.copy()
            timed["Saat"] = pd.to_datetime(
                timed["Zaman"],
                utc=True,
                errors="coerce",
            ).dt.floor("h")

            timeline = timed.dropna(subset=["Saat"]).groupby(
                ["Saat", "Sonuç"]
            ).size().reset_index(name="Olay")

            if timeline.empty:
                st.caption("Gösterilecek olay yok.")
            else:
                plot(px.line(
                    timeline,
                    x="Saat",
                    y="Olay",
                    color="Sonuç",
                    markers=True,
                    color_discrete_map=COLORS,
                ))

    with second:
        with st.container(border=True):
            st.subheader("Alarm Türleri")

            if alarm_table.empty:
                st.caption("Gösterilecek alarm yok.")
            else:
                counts = alarm_table["Kural"].value_counts()
                st.dataframe(
                    counts.rename_axis("Kural").reset_index(name="Alarm"),
                    width="stretch",
                    hide_index=True,
                )

            st.divider()
            st.metric("Log İşleme Hızı", "—")
            st.caption("İçe aktarma süresi henüz ölçülmüyor.")

    with third:
        with st.container(border=True):
            st.subheader("Giriş Sonuçları")

            counts = events["Sonuç"].value_counts().rename_axis(
                "Sonuç"
            ).reset_index(name="Olay")

            if counts.empty:
                st.caption("Gösterilecek olay yok.")
            else:
                plot(px.pie(
                    counts,
                    names="Sonuç",
                    values="Olay",
                    hole=0.68,
                    color="Sonuç",
                    color_discrete_map=COLORS,
                ))

    left, right = st.columns(2)

    with left:
        with st.container(border=True):
            st.subheader("Son Alarmlar")
            st.dataframe(
                alarm_table.head(10),
                width="stretch",
                hide_index=True,
            )

    with right:
        with st.container(border=True):
            st.subheader("En Çok Başarısız Giriş Yapan IP’ler")

            top = failures[failures["IP"] != "Yok"].groupby("IP").agg(
                Deneme=("IP", "size"),
                Kullanıcı=("Kullanıcı", "nunique"),
                Sunucu=("Sunucu", "nunique"),
            ).reset_index().sort_values(
                "Deneme",
                ascending=False,
            )

            st.dataframe(
                top.head(10),
                width="stretch",
                hide_index=True,
            )

elif page == "Olay İnceleme":
    left, right = st.columns([2, 1])

    search = left.text_input("IP veya kullanıcı ara")
    result = right.selectbox(
        "Sonuç",
        ["Tümü", "Başarılı", "Başarısız"],
    )
    filtered = events.copy()

    if search:
        filtered = filtered[
            filtered["IP"].str.contains(
                search, case=False, regex=False
            )
            | filtered["Kullanıcı"].str.contains(
                search, case=False, regex=False
            )
        ]

    if result != "Tümü":
        filtered = filtered[filtered["Sonuç"] == result]

    st.caption(f"{len(filtered)} kayıt bulundu.")

    st.dataframe(
        filtered.drop(columns=["Ham Log"]),
        width="stretch",
        hide_index=True,
    )

    if not filtered.empty:
        selected = st.selectbox(
            "Ham Olay Detayı",
            filtered.index.tolist(),
            format_func=lambda i: (
                f"{events.loc[i, 'Zaman']} | "
                f"{events.loc[i, 'IP']} | "
                f"{events.loc[i, 'Kullanıcı']}"
            ),
        )
        st.code(
            events.loc[selected, "Ham Log"],
            language="text",
        )

elif page == "Alarm Merkezi":
    st.caption(
        f"Eşik: {threshold} · Pencere: {minutes} dakika. "
        "Çok kullanıcı kuralında eşik farklı kullanıcı sayısıdır."
    )
    st.caption(
        "Alarm inceleme gerektiren bir bulgudur. "
        "Önem seviyesi, not ve durum aşağıdaki Alarm Yönetimi bölümünden kaydedilir."
    )

    rule_filter = st.selectbox(
        "Kural Filtresi",
        ["Tümü"] + sorted(alarm_table["Kural"].unique().tolist()),
    )

    visible_alerts = [
        alarm for alarm in alerts
        if rule_filter == "Tümü" or alarm["Kural"] == rule_filter
    ]

    visible_table = alarm_table.copy()

    if rule_filter != "Tümü":
        visible_table = visible_table[
            visible_table["Kural"] == rule_filter
        ]

    st.metric("Gösterilen Alarm", len(visible_alerts))

    st.dataframe(
        visible_table,
        width="stretch",
        hide_index=True,
    )

    if visible_alerts:
        selected = st.selectbox(
            "Alarm Seç",
            range(len(visible_alerts)),
            format_func=lambda i: (
                f"{visible_alerts[i]['Kural']} | "
                f"{visible_alerts[i]['IP']} | "
                f"{visible_alerts[i]['Zaman']}"
            ),
        )
        alarm = visible_alerts[selected]

        with st.container(border=True):
            st.subheader(alarm["Kural"])
            st.write(
                f"**Kaynak:** {alarm['Kaynak']} · "
                f"**Sunucu:** {alarm['Sunucu']} · "
                f"**IP:** {alarm['IP']}"
            )
            st.caption(f"Alarm zamanı (UTC): {alarm['Zaman']}")

            if alarm["Kural"] == "Başarısızlık sonrası başarılı giriş":
                st.caption(
                    "Kanıt sayısı, başarısız girişlere ek olarak "
                    "son başarılı girişi de içerir."
                )

            st.dataframe(
                alarm["Kanıt"].drop(columns=["Ham Log"]),
                width="stretch",
                hide_index=True,
            )

    else:
        st.info("Seçilen filtre ve eşiklere uyan alarm bulunmadı.")

    missing = int((failures["IP"] == "Yok").sum())

    if missing:
        st.caption(
            f"IP bilgisi olmayan {missing} başarısız olay "
            "kurallara dahil edilmedi."
        )

elif page == "Raporlar":
    st.subheader("Filtrelenmiş Kayıtları Dışa Aktar")

    st.download_button(
        "Olayları CSV İndir",
        events.drop(columns=["Ham Log"]).to_csv(
            index=False
        ).encode("utf-8-sig"),
        file_name="sentinellog_events.csv",
        mime="text/csv",
    )

    st.download_button(
        "Alarmları CSV İndir",
        alarm_table.to_csv(index=False).encode("utf-8-sig"),
        file_name="sentinellog_alerts.csv",
        mime="text/csv",
    )

    st.caption(
        "PDF raporlama ve bildirimler sonraki aşamada eklenecek."
    )

if page == "Alarm Merkezi":
    from alarm_management import render_alarm_management
    render_alarm_management(visible_alerts)