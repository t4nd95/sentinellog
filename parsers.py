import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime

import pandas as pd
from Evtx.Evtx import Evtx

from database import COLUMNS

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

SSH_HEADER = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)

SSH_LOGIN = re.compile(
    r"^(?P<result>Failed|Accepted)\s+"
    r"(?:password|publickey)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+\d+\b"
)


def normalize_ip(value):
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address):
            address = address.ipv4_mapped or address
        return str(address)
    except ValueError:
        return "Yok"


def parse_windows(path):
    rows = []
    skipped = 0

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                raw = record.xml()
                root = ET.fromstring(raw)

                event_id = root.findtext(
                    "e:System/e:EventID", default="", namespaces=NS
                )
                host = root.findtext(
                    "e:System/e:Computer", default="", namespaces=NS
                )
                provider = root.find("e:System/e:Provider", NS)
                time_node = root.find("e:System/e:TimeCreated", NS)

                if (
                    provider is None
                    or provider.get("Name")
                    != "Microsoft-Windows-Security-Auditing"
                    or event_id not in {"4624", "4625"}
                    or time_node is None
                ):
                    skipped += 1
                    continue

                timestamp = pd.to_datetime(
                    time_node.get("SystemTime"),
                    utc=True,
                    errors="coerce",
                )
                if pd.isna(timestamp):
                    skipped += 1
                    continue

                data = {
                    node.get("Name"): node.text or ""
                    for node in root.findall("e:EventData/e:Data", NS)
                }

                username = data.get("TargetUserName", "")
                domain = data.get("TargetDomainName", "")

                if username in {"", "-"}:
                    username = "Bilinmiyor"
                elif domain not in {"", "-"}:
                    username = f"{domain}\\{username}"

                rows.append({
                    "Zaman": timestamp.isoformat(),
                    "Kaynak": "Windows",
                    "Sunucu": host or "Bilinmiyor",
                    "Event ID": event_id,
                    "IP": normalize_ip(data.get("IpAddress", "")),
                    "Kullanıcı": username,
                    "Sonuç": (
                        "Başarılı" if event_id == "4624"
                        else "Başarısız"
                    ),
                    "Ham Log": raw,
                })

            except (ET.ParseError, ValueError, KeyError):
                skipped += 1

    return pd.DataFrame(rows, columns=COLUMNS), skipped


def parse_ssh(text, year, timezone):
    rows = []
    skipped = 0

    for line in text.splitlines():
        if not line.strip():
            continue

        try:
            header = SSH_HEADER.match(line)
            login = SSH_LOGIN.match(header["message"]) if header else None

            if not login:
                skipped += 1
                continue

            value = header["time"]

            if re.match(r"^\d{4}-", value):
                timestamp = pd.Timestamp(value)
            else:
                month, day, clock = value.split()
                hour, minute, second = map(int, clock.split(":"))
                timestamp = pd.Timestamp(datetime(
                    year, MONTHS[month], int(day),
                    hour, minute, second,
                ))

            if timestamp.tzinfo is None:
                timestamp = timestamp.tz_localize(
                    timezone,
                    ambiguous="raise",
                    nonexistent="raise",
                )

            timestamp = timestamp.tz_convert("UTC")
            address = normalize_ip(login["ip"])

            if address == "Yok":
                skipped += 1
                continue

            rows.append({
                "Zaman": timestamp.isoformat(),
                "Kaynak": "Linux SSH",
                "Sunucu": header["host"],
                "Event ID": "",
                "IP": address,
                "Kullanıcı": login["user"],
                "Sonuç": (
                    "Başarılı" if login["result"] == "Accepted"
                    else "Başarısız"
                ),
                "Ham Log": line,
            })

        except (ValueError, KeyError, OverflowError):
            skipped += 1

    return pd.DataFrame(rows, columns=COLUMNS), skipped