from collections import Counter, deque

import pandas as pd


RULES = [
    "Tekrarlanan başarısız giriş",
    "Çok kullanıcıya giriş denemesi",
    "Başarısızlık sonrası başarılı giriş",
]


def detect_alerts(events, threshold, minutes):
    if events.empty:
        return []

    data = events.copy()
    data["_time"] = pd.to_datetime(
        data["Zaman"], utc=True, errors="coerce"
    )
    data = data.dropna(subset=["_time"])
    data = data[data["IP"].notna() & (data["IP"] != "Yok")]
    data = data.sort_values("_time", kind="stable")

    window = pd.Timedelta(minutes=minutes)
    alerts = []

    def add_alert(rule, group, indexes, timestamp):
        evidence = group.loc[indexes].drop(columns=["_time"]).copy()
        last = evidence.iloc[-1]

        alerts.append({
            "Kural": rule,
            "Zaman": timestamp,
            "Kaynak": last["Kaynak"],
            "Sunucu": last["Sunucu"],
            "IP": last["IP"],
            "Sayı": len(evidence),
            "Kanıt": evidence,
        })

    for _, group in data.groupby(["Kaynak", "Sunucu", "IP"]):
        group = group.reset_index(drop=True)
        failure_window = deque()
        users = Counter()
        brute_found = False
        multiple_found = False

        # İlk iki kural: aynı IP, sunucu ve kaynak.
        for index, row in group.iterrows():
            if row["Sonuç"] != "Başarısız":
                continue

            current = row["_time"]

            while (
                failure_window
                and current - group.loc[failure_window[0], "_time"] > window
            ):
                old_index = failure_window.popleft()
                old_user = str(group.loc[old_index, "Kullanıcı"]).strip()
                if old_user not in {"", "-", "Bilinmiyor"}:
                    users[old_user] -= 1
                    if users[old_user] == 0:
                        del users[old_user]

            failure_window.append(index)
            username = str(row["Kullanıcı"]).strip()

            if username not in {"", "-", "Bilinmiyor"}:
                users[username] += 1

            if not brute_found and len(failure_window) >= threshold:
                add_alert(
                    RULES[0], group, list(failure_window), current
                )
                brute_found = True

            if not multiple_found and len(users) >= threshold:
                add_alert(
                    RULES[1], group, list(failure_window), current
                )
                multiple_found = True

        # Üçüncü kural: aynı IP, sunucu, kaynak VE kullanıcı.
        # Başarılı giriş, kendisinden önceki başarısızlıklarla eşleşir.
        for username, user_group in group.groupby("Kullanıcı"):
            if str(username).strip() in {"", "-", "Bilinmiyor"}:
                continue

            pending = deque()

            for index, row in user_group.iterrows():
                current = row["_time"]

                while (
                    pending
                    and current - group.loc[pending[0], "_time"] > window
                ):
                    pending.popleft()

                if row["Sonuç"] == "Başarısız":
                    pending.append(index)

                elif row["Sonuç"] == "Başarılı":
                    previous = [
                        i for i in pending
                        if group.loc[i, "_time"] < current
                    ]

                    if len(previous) >= threshold:
                        add_alert(
                            RULES[2], group, previous + [index], current
                        )
                        break

                    # Son başarılı girişten önceki denemeleri sıfırla.
                    pending.clear()

    return sorted(
        alerts,
        key=lambda item: item["Zaman"],
        reverse=True,
    )