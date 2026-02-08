#!/usr/bin/env python3
"""
Windows Event Log Triage Tool
.evtx dosyasını okuyup şüpheli aktiviteleri işaretleyen ve HTML rapor üreten araç.
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

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

# İzlenecek Event ID'ler
EVENT_4625 = "4625"   # Başarısız login
EVENT_4624 = "4624"   # Başarılı login (gece + RDP kontrolü)
EVENT_4720 = "4720"   # Kullanıcı oluşturma
EVENT_4672 = "4672"   # Admin yetkisi
EVENT_1102 = "1102"   # Log silme
LOGON_TYPE_RDP = "10" # RemoteInteractive (RDP)

# Önem seviyeleri
LEVEL_CRITICAL = "critical"   # Kırmızı
LEVEL_SUSPICIOUS = "suspicious"  # Sarı
LEVEL_NORMAL = "normal"       # Yeşil


def get_element_text(parent, tag, default=""):
    """XML elementinden metin al (namespace ile)."""
    el = parent.find(f"win:{tag}", NS)
    if el is not None and el.text:
        return el.text.strip()
    return default


def get_event_data_dict(root):
    """EventData altındaki Data elementlerini Name -> text sözlüğü yap."""
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
    """Windows SystemTime string'ini datetime'a çevir."""
    if not system_time_str:
        return None
    try:
        # Format: 2024-01-15T14:30:00.0000000Z
        return datetime.fromisoformat(system_time_str.replace("Z", "+00:00"))
    except Exception:
        return None


def get_event_id(root):
    """EventID değerini al (bazen Qualifiers ile birlikte gelir)."""
    el = root.find("win:System/win:EventID", NS)
    if el is not None and el.text:
        return el.text.strip()
    return None


def get_time_created(root):
    """TimeCreated SystemTime değerini al."""
    el = root.find("win:System/win:TimeCreated", NS)
    if el is not None:
        return el.get("SystemTime", "")
    return ""


def analyze_record(record):
    """
    Tek bir EVTX kaydını parse et; ilgili EventID'ler için sınıflandırılmış olay döndür.
    """
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

    # Sadece izlediğimiz event'leri topla
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
        return {
            "event_id": event_id,
            "time": time_created,
            "dt": dt,
            "level": LEVEL_CRITICAL,
            "description": f"Başarısız giriş: {target} (IP: {ip}, Status: {status})",
            "data": data,
        }

    if event_id == EVENT_4624:
        target = data.get("TargetUserName", "?")
        logon_type = data.get("LogonType", "")
        ip = data.get("IpAddress", "-")
        is_rdp = logon_type == LOGON_TYPE_RDP
        # Gece 00:00 - 06:00
        is_night = False
        if dt:
            hour = dt.hour
            if dt.tzinfo:
                # UTC ise locale'e çevirmiyoruz; kullanıcı rapora bakarak yorumlar
                hour = dt.hour
            is_night = 0 <= hour < 6

        if is_night and is_rdp:
            level = LEVEL_SUSPICIOUS
            desc = f"Gece RDP girişi (00-06): {target} (IP: {ip})"
        elif is_night:
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
        }

    return None


def analyze_evtx(evtx_path):
    """EVTX dosyasını okuyup ilgili olayları çıkar."""
    path = Path(evtx_path)
    if not path.exists():
        raise FileNotFoundError(f"Dosya bulunamadı: {evtx_path}")
    if path.suffix.lower() != ".evtx":
        print("Uyarı: Dosya .evtx uzantılı değil.")

    events = []

    with Evtx(str(path)) as log:
        for record in log.records():
            ev = analyze_record(record)
            if ev:
                events.append(ev)

    # Zamana göre sırala
    def sort_key(e):
        if e.get("dt"):
            return e["dt"]
        return datetime.min

    events.sort(key=sort_key)
    return events



def format_time_display(ev):
    """Olay zamanını rapor için gösterilebilir formata çevir."""
    dt = ev.get("dt")
    if dt:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return ev.get("time", "?")


def generate_html_report(events, evtx_path, output_path):
    """HTML rapor ve zaman çizelgesi oluştur."""
    path = Path(evtx_path)
    out = Path(output_path)
    if not out.suffix.lower() == ".html":
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
            color = "#c0392b"
            bg = "#fadbd8"
        elif level == LEVEL_SUSPICIOUS:
            color = "#b7950b"
            bg = "#fcf3cf"
        else:
            color = "#1e8449"
            bg = "#d5f5e3"
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
        h2 {{ color: #34495e; margin-top: 28px; }}
        .meta {{ color: #7f8c8d; font-size: 14px; margin-bottom: 20px; }}
        .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }}
        .badge {{ padding: 10px 16px; border-radius: 6px; color: white; font-weight: bold; }}
        .badge.critical {{ background: #c0392b; }}
        .badge.suspicious {{ background: #b7950b; }}
        .badge.normal {{ background: #1e8449; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }}
        th {{ background: #34495e; color: white; }}
        tr:hover {{ background-color: #f8f9fa !important; }}
        .legend {{ margin: 16px 0; padding: 12px; background: #ecf0f1; border-radius: 6px; }}
        .legend span {{ margin-right: 20px; }}
        footer {{ margin-top: 32px; color: #95a5a6; font-size: 12px; }}
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
            Tespit edilen Event ID'ler: 4625 (başarısız giriş), 4624 (gece girişi / RDP), 4720 (kullanıcı oluşturma), 4672 (admin yetkisi), 1102 (log silme).
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
    parser.add_argument(
        "evtx_file",
        type=str,
        help="Analiz edilecek .evtx dosyasının yolu",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="HTML rapor çıktı dosyası (varsayılan: <evtx_adı>_report.html)",
    )
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
