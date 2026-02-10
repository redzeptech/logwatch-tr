#!/usr/bin/env python3
"""
Windows Event Log Triage Tool
Reads .evtx and produces an HTML timeline report + quick incident insights.
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from actor_classifier import classify_logon_event

try:
    from Evtx.Evtx import Evtx
except Exception as e:
    print("Hata: python-evtx modülü import edilemedi.")
    print("Detay:", repr(e))
    print("Çözüm: python -m pip install --upgrade python-evtx")
    raise

try:
    import xml.etree.ElementTree as ET
except ImportError:
    import xml.etree.cElementTree as ET

# Windows Event Log XML namespace
NS = {"win": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Target Event IDs
EVENT_4625 = "4625"   # Failed logon
EVENT_4624 = "4624"   # Successful logon
EVENT_4720 = "4720"   # User created
EVENT_4672 = "4672"   # Special privileges assigned
EVENT_1102 = "1102"   # Audit log cleared
LOGON_TYPE_RDP = "10" # RemoteInteractive (RDP)

# Severity levels
LEVEL_CRITICAL = "critical"
LEVEL_SUSPICIOUS = "suspicious"
LEVEL_NORMAL = "normal"


def get_event_data_dict(root):
    """EventData/Data elements -> dict(Name -> text)."""
    event_data = root.find("win:EventData", NS)
    if event_data is None:
        return {}
    result = {}
    for data in event_data.findall("win:Data", NS):
        name = data.get("Name")
        if name:
            result[name] = (data.text or "").strip()
    return result


def parse_time(system_time_str):
    """Convert Windows SystemTime string to datetime (timezone aware if Z)."""
    if not system_time_str:
        return None
    try:
        return datetime.fromisoformat(system_time_str.replace("Z", "+00:00"))
    except Exception:
        return None


def get_event_id(root):
    el = root.find("win:System/win:EventID", NS)
    if el is not None and el.text:
        return el.text.strip()
    return None


def get_time_created(root):
    el = root.find("win:System/win:TimeCreated", NS)
    if el is not None:
        return el.get("SystemTime", "")
    return ""


def analyze_record(record):
    """Parse a single EVTX record and return normalized event dict (or None)."""
    try:
        xml_str = record.xml()
    except Exception:
        return None
    if not xml_str:
        return None

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    event_id = get_event_id(root)
    if not event_id:
        return None

    time_created = get_time_created(root)
    dt = parse_time(time_created)
    data = get_event_data_dict(root)

    if event_id == EVENT_1102:
        return {
            "event_id": event_id,
            "time": time_created,
            "dt": dt,
            "level": LEVEL_CRITICAL,
            "description": "Log silme (Audit Log Cleared)",
            "data": data,
        }

    if event_id == EVENT_4720:
        target = data.get("TargetUserName", "?")
        subject = data.get("SubjectUserName", "?")
        return {
            "event_id": event_id,
            "time": time_created,
            "dt": dt,
            "level": LEVEL_CRITICAL,
            "description": f"Kullanıcı oluşturuldu: {target} (oluşturan: {subject})",
            "data": data,
        }

    if event_id == EVENT_4672:
        subject = data.get("SubjectUserName", "?")

        # reduce false positives from SYSTEM
        if subject and subject.upper() == "SYSTEM":
            return None

        return {
            "event_id": event_id,
            "time": time_created,
            "dt": dt,
            "level": LEVEL_SUSPICIOUS,
            "description": f"Özel yetkiler atandı (Admin): {subject}",
            "data": data,
        }

    if event_id == EVENT_4625:
        target = data.get("TargetUserName", "?")
        ip = data.get("IpAddress", "-")
        status = data.get("Status", "?")
        actor = classify_logon_event(data)
        return {
            "event_id": event_id,
            "time": time_created,
            "dt": dt,
            "level": LEVEL_CRITICAL,
            "description": f"Başarısız giriş: {target} (IP: {ip}, Status: {status})",
            "data": data,
            "actor_type": actor.actor_type,
            "actor_confidence": actor.confidence,
            "actor_reason": actor.reason,
        }

    if event_id == EVENT_4624:
        target = data.get("TargetUserName", "?")
        logon_type = data.get("LogonType", "")
        ip = data.get("IpAddress", "-")
        is_rdp = (logon_type == LOGON_TYPE_RDP)
        actor = classify_logon_event(data)

        # 00:00-06:00 (based on event dt hour)
        is_night = False
        if dt:
            is_night = 0 <= dt.hour < 6

        if is_night and is_rdp and actor.actor_type in {"human", "local_builtin"}:
            level = LEVEL_SUSPICIOUS
            desc = f"Gece RDP girişi (00-06): {target} (IP: {ip})"
        elif is_night and actor.actor_type in {"human", "local_builtin"}:
            level = LEVEL_SUSPICIOUS
            desc = f"Gece girişi (00-06): {target} (IP: {ip}, LogonType: {logon_type})"
        elif is_rdp:
            level = LEVEL_NORMAL
            desc = f"RDP girişi (LogonType 10): {target} (IP: {ip})"
        else:
            level = LEVEL_NORMAL
            desc = f"Başarılı giriş: {target} (IP: {ip}, LogonType: {logon_type})"

        return {
            "event_id": event_id,
            "time": time_created,
            "dt": dt,
            "level": level,
            "description": desc,
            "data": data,
            "logon_type": logon_type,
            "is_rdp": is_rdp,
            "is_night": is_night,
            "actor_type": actor.actor_type,
            "actor_confidence": actor.confidence,
            "actor_reason": actor.reason,
        }

    return None


def analyze_evtx(evtx_path):
    path = Path(evtx_path)
    if not path.exists():
        raise FileNotFoundError(f"Dosya bulunamadı: {evtx_path}")

    events = []
    with Evtx(str(path)) as log:
        for record in log.records():
            ev = analyze_record(record)
            if ev:
                events.append(ev)

    events.sort(key=lambda e: e["dt"] if e.get("dt") else datetime.min)
    return events


def format_time_display(ev):
    dt = ev.get("dt")
    if dt:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return ev.get("time", "?")


def generate_insights(events, window_minutes=10, threshold=30):
    """Generate human-readable insights from normalized events."""
    insights = []

    if not events:
        return ["İlgili olay bulunamadı."]

    # 1102
    cleared = [e for e in events if str(e.get("event_id")) == EVENT_1102]
    if cleared:
        t = cleared[-1].get("dt")
        ts = t.strftime("%Y-%m-%d %H:%M:%S") if t else cleared[-1].get("time", "?")
        insights.append(f"🧨 Audit Log Cleared (1102) tespit edildi. Zaman: {ts} (iz silme şüphesi).")

    # brute-force 4625 by IP/user in sliding window
    failed = [e for e in events if str(e.get("event_id")) == EVENT_4625 and e.get("dt")]
    failed.sort(key=lambda x: x["dt"])

    def get_ip(ev):
        return (ev.get("data") or {}).get("IpAddress") or "-"

    def get_user(ev):
        return (ev.get("data") or {}).get("TargetUserName") or "?"

    def detect_burst(items, key_func, label):
        i = 0
        best = {}  # key -> (count, start, end)
        for j in range(len(items)):
            while items[j]["dt"] - items[i]["dt"] > timedelta(minutes=window_minutes):
                i += 1
            window = items[i:j+1]
            k = key_func(items[j])
            if k == "-":  # ignore missing IP
                continue
            cnt = sum(1 for x in window if key_func(x) == k)
            if cnt >= threshold:
                s = window[0]["dt"].strftime("%Y-%m-%d %H:%M:%S")
                e = window[-1]["dt"].strftime("%Y-%m-%d %H:%M:%S")
                if (k not in best) or (cnt > best[k][0]):
                    best[k] = (cnt, s, e)
        for k, (cnt, s, e) in sorted(best.items(), key=lambda x: x[1][0], reverse=True)[:3]:
            insights.append(f"🚨 Olası brute-force ({label}): {k} için {window_minutes} dk içinde {cnt} başarısız giriş (4625). {s} → {e}")

    if failed:
        detect_burst(failed, get_ip, "IP")
        detect_burst(failed, get_user, "Kullanıcı")

    # night RDP
    rdp_night = [
        e for e in events
        if str(e.get("event_id")) == EVENT_4624
        and e.get("is_rdp")
        and e.get("is_night")
        and e.get("dt")
        and e.get("actor_type") in {"human", "local_builtin"}
    ]
    if rdp_night:
        users = Counter(((e.get("data") or {}).get("TargetUserName") or "?") for e in rdp_night)
        ips = Counter(((e.get("data") or {}).get("IpAddress") or "-") for e in rdp_night)
        u, uc = users.most_common(1)[0]
        ip, ipc = ips.most_common(1)[0]
        insights.append(f"🌙 Gece RDP (00-06) tespit edildi: {len(rdp_night)} olay. En sık kullanıcı: {u} ({uc}), IP: {ip} ({ipc}).")

    # priv escalation heuristic: 4624 then 4672 within 5 minutes (same username)
    logins = [e for e in events if str(e.get("event_id")) == EVENT_4624 and e.get("dt")]
    privs = [e for e in events if str(e.get("event_id")) == EVENT_4672 and e.get("dt")]
    login_by_user = defaultdict(list)
    for e in logins:
        u = (e.get("data") or {}).get("TargetUserName") or "?"
        login_by_user[u].append(e["dt"])

    for p in privs:
        u = (p.get("data") or {}).get("SubjectUserName") or "?"
        pdt = p["dt"]
        for ldt in login_by_user.get(u, []):
            if timedelta(0) <= (pdt - ldt) <= timedelta(minutes=5):
                insights.append(
                    f"⬆️ Olası yetki yükseltme: '{u}' girişten ≤5 dk sonra özel yetki aldı (4672). "
                    f"{ldt.strftime('%Y-%m-%d %H:%M:%S')} → {pdt.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                # report one example only
                return insights

    if not insights:
        insights.append("ℹ️ Belirgin korelasyon bulunamadı. Zaman çizelgesini inceleyin.")

    return insights


def generate_html_report(events, evtx_path, output_path):
    path = Path(evtx_path)
    out = Path(output_path)
    if out.suffix.lower() != ".html":
        out = out.with_suffix(".html")

    by_level = defaultdict(list)
    for ev in events:
        by_level[ev["level"]].append(ev)

    critical_count = len(by_level[LEVEL_CRITICAL])
    suspicious_count = len(by_level[LEVEL_SUSPICIOUS])
    normal_count = len(by_level[LEVEL_NORMAL])

    rows = []
    for ev in events:
        level = ev["level"]
        if level == LEVEL_CRITICAL:
            color = "#c0392b"; bg = "#fadbd8"
        elif level == LEVEL_SUSPICIOUS:
            color = "#b7950b"; bg = "#fcf3cf"
        else:
            color = "#1e8449"; bg = "#d5f5e3"

        time_str = format_time_display(ev)
        rows.append(
            f"""
            <tr style="background-color: {bg};">
                <td>{time_str}</td>
                <td><strong>{ev['event_id']}</strong></td>
                <td style="color: {color}; font-weight: bold;">{ev['level'].upper()}</td>
                <td>{ev['description']}</td>
            </tr>
            """
        )

    timeline_rows = "".join(rows)
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    insights = generate_insights(events, window_minutes=10, threshold=30)
    insights_html = "".join(f"<li>{i}</li>" for i in insights)

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EVTX Triage Raporu - {path.name}</title>
  <style>
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 24px; background: #f5f5f5; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 8px; }}
    h2 {{ color: #34495e; margin-top: 24px; }}
    .meta {{ color: #7f8c8d; font-size: 14px; margin-bottom: 20px; }}
    .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
    .badge {{ padding: 10px 16px; border-radius: 6px; color: white; font-weight: bold; }}
    .badge.critical {{ background: #c0392b; }}
    .badge.suspicious {{ background: #b7950b; }}
    .badge.normal {{ background: #1e8449; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }}
    th {{ background: #34495e; color: white; }}
    tr:hover {{ background-color: #f8f9fa !important; }}
    .legend {{ margin: 16px 0; padding: 12px; background: #ecf0f1; border-radius: 6px; }}
    footer {{ margin-top: 28px; color: #95a5a6; font-size: 12px; }}
    ul {{ line-height: 1.55; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Windows Event Log Triage Raporu</h1>

    <div class="meta">
      Dosya: <strong>{path.name}</strong><br>
      Rapor tarihi: {report_time}<br>
      Toplam işaretlenen olay: <strong>{len(events)}</strong>
    </div>

    <div class="summary">
      <span class="badge critical">Kritik: {critical_count}</span>
      <span class="badge suspicious">Şüpheli: {suspicious_count}</span>
      <span class="badge normal">Normal: {normal_count}</span>
    </div>

    <div class="legend">
      <strong>Renk açıklaması:</strong>
      <span style="color: #c0392b;">Kırmızı = Kritik</span>
      <span style="color: #b7950b;">Sarı = Şüpheli</span>
      <span style="color: #1e8449;">Yeşil = Normal</span>
    </div>

    <h2>Incident Insights</h2>
    <ul>
      {insights_html}
    </ul>

    <h2>Zaman Çizelgesi</h2>
    <table>
      <thead>
        <tr>
          <th>Zaman</th>
          <th>Event ID</th>
          <th>Seviye</th>
          <th>Açıklama</th>
        </tr>
      </thead>
      <tbody>
        {timeline_rows}
      </tbody>
    </table>

    <footer>
      LogWatch EVTX Triage | python-evtx ile oluşturuldu.
      Tespit edilen Event ID'ler: 4625, 4624, 4720, 4672, 1102.
    </footer>
  </div>
</body>
</html>
"""
    out.write_text(html, encoding="utf-8")
    return str(out)


def main():
    parser = argparse.ArgumentParser(
        description="Windows Event Log (.evtx) triage aracı - şüpheli aktiviteleri işaretleyip HTML rapor üretir."
    )
    parser.add_argument("evtx_file", type=str, help="Analiz edilecek .evtx dosyasının yolu")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="HTML rapor çıktı dosyası (varsayılan: <evtx_adı>_report.html)")
    args = parser.parse_args()

    evtx_path = args.evtx_file
    output_path = args.output
    if not output_path:
        output_path = Path(evtx_path).stem + "_report.html"

    print(f"EVTX dosyası okunuyor: {evtx_path}")
    try:
        events = analyze_evtx(evtx_path)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Hata: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Toplam {len(events)} ilgili olay bulundu.")
    critical = sum(1 for e in events if e["level"] == LEVEL_CRITICAL)
    suspicious = sum(1 for e in events if e["level"] == LEVEL_SUSPICIOUS)
    normal = sum(1 for e in events if e["level"] == LEVEL_NORMAL)
    print(f"  - Kritik: {critical}, Şüpheli: {suspicious}, Normal: {normal}")

    out_file = generate_html_report(events, evtx_path, output_path)
    print(f"HTML rapor kaydedildi: {out_file}")


if __name__ == "__main__":
    main()
