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

        # SYSTEM servis logonlarını filtrele (false positive azaltma)
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
from collections import Counter, defaultdict
from datetime import timedelta

def _safe_dt(ev):
    return ev.get("dt")

def generate_insights(events, window_minutes=10, threshold=30):
    """
    Basit korelasyonlar ile 'Incident Insights' üretir.
    - Brute force: aynı IP veya kullanıcıya window içinde >= threshold başarısız deneme
    - Gece RDP: 00:00-06:00 arası RDP logon (Type 10)
    - Privilege escalation: login (4624) sonrası kısa sürede (<=5 dk) 4672
    - Log cleared: 1102
    """
    insights = []

    if not events:
        return ["İlgili olay bulunamadı (filtrelenen EventID seti içinde)."]

    # --- 1102 Log cleared ---
    cleared = [e for e in events if str(e.get("event_id")) == "1102"]
    if cleared:
        t = cleared[-1].get("dt")
        ts = t.strftime("%Y-%m-%d %H:%M:%S") if t else cleared[-1].get("time", "?")
        insights.append(f"🧨 Audit Log Cleared (1102) tespit edildi. Olay zamanı: {ts}. Bu genellikle iz silme girişimidir.")

    # --- Brute-force (4625) by IP / user in sliding window ---
    failed = [e for e in events if str(e.get("event_id")) == "4625" and _safe_dt(e)]
    failed.sort(key=lambda x: x["dt"])

    def key_ip(ev):
        return (ev.get("data") or {}).get("IpAddress") or "-"

    def key_user(ev):
        return (ev.get("data") or {}).get("TargetUserName") or "?"

    # Bucket by IP and by user (sliding window)
    def detect_burst(items, key_func, label):
        bursts = []
        i = 0
        for j in range(len(items)):
            while items[j]["dt"] - items[i]["dt"] > timedelta(minutes=window_minutes):
                i += 1
            # window size
            if (j - i + 1) >= threshold:
                k = key_func(items[j])
                # count within window for that key
                window = items[i:j+1]
                cnt = sum(1 for x in window if key_func(x) == k)
                if cnt >= threshold:
                    start = window[0]["dt"].strftime("%Y-%m-%d %H:%M:%S")
                    end = window[-1]["dt"].strftime("%Y-%m-%d %H:%M:%S")
                    bursts.append((k, cnt, start, end))
        # dedupe: keep top unique keys
        best = {}
        for k, cnt, s, e in bursts:
            if k not in best or cnt > best[k][0]:
                best[k] = (cnt, s, e)
        out = sorted([(k, *v) for k, v in best.items()], key=lambda x: x[1], reverse=True)
        if out:
            top = out[:3]
            for k, cnt, s, e in top:
                insights.append(
                    f"🚨 Olası brute-force ({label}): {k} için {window_minutes} dk içinde {cnt} başarısız giriş (4625). Zaman aralığı: {s} → {e}."
                )

    if failed:
        detect_burst(failed, key_ip, "IP")
        detect_burst(failed, key_user, "Kullanıcı")

    # --- Night RDP logins ---
    rdp_night = [
        e for e in events
        if str(e.get("event_id")) == "4624"
        and e.get("is_rdp")
        and e.get("is_night")
        and _safe_dt(e)
    ]
    if rdp_night:
        # summarize top users/IPs
        users = Counter(((e.get("data") or {}).get("TargetUserName") or "?") for e in rdp_night)
        ips = Counter(((e.get("data") or {}).get("IpAddress") or "-") for e in rdp_night)
        top_user = users.most_common(1)[0]
        top_ip = ips.most_common(1)[0]
        insights.append(
            f"🌙 Gece RDP oturumu (00-06) tespit edildi: toplam {len(rdp_night)} olay. En sık kullanıcı: {top_user[0]} ({top_user[1]}), en sık IP: {top_ip[0]} ({top_ip[1]})."
        )

    # --- Privilege escalation heuristic: 4624 then 4672 within 5 minutes for same SubjectUserName ---
    # 4672 uses SubjectUserName; 4624 uses TargetUserName in your parse.
    logins = [e for e in events if str(e.get("event_id")) == "4624" and _safe_dt(e)]
    privs = [e for e in events if str(e.get("event_id")) == "4672" and _safe_dt(e)]
    logins.sort(key=lambda x: x["dt"])
    privs.sort(key=lambda x: x["dt"])

    # index logins by user
    login_by_user = defaultdict(list)
    for e in logins:
        u = (e.get("data") or {}).get("TargetUserName") or "?"
        login_by_user[u].append(e["dt"])

    escalations = []
    for p in privs:
        u = (p.get("data") or {}).get("SubjectUserName") or "?"
        pdt = p["dt"]
        for ldt in login_by_user.get(u, []):
            if timedelta(0) <= (pdt - ldt) <= timedelta(minutes=5):
                escalations.append((u, ldt, pdt))
                break

    if escalations:
        u, ldt, pdt = escalations[0]
        insights.append(
            f"⬆️ Olası yetki yükseltme: '{u}' kullanıcısı girişten kısa süre sonra (≤5 dk) özel yetki aldı (4672). {ldt.strftime('%Y-%m-%d %H:%M:%S')} → {pdt.strftime('%Y-%m-%d %H:%M:%S')}"
        )

    # fallback
    if not insights:
        insights.append("ℹ️ Belirgin korelasyon bulunamadı. Zaman çizelgesini kritik/şüpheli olaylar için inceleyin.")

    return insights


def generate_html_report(events, evtx_path, output_path):
    """HTML rapor ve zaman çizelgesi oluştur."""
    path = Path(evtx_path)
    out = Path(output_path)
    if not out.suffix.lower() == ".html":
        out = out.with_suffix(".html")
    insights = brute_force_insights(events, window_minutes=10, threshold=30)


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
                <h2>Hızlı Triage Özeti (4625)</h2>
        <div class="legend">
            <strong>Durum:</strong> {alert_text}<br>
            <strong>Toplam 4625:</strong> {insights["failed_total"]}<br>
            <strong>En yoğun pencere:</strong> {ww_text}
        </div>

        <div class="summary">
            <div style="flex:1; min-width:280px;">
                <h3>Top IP (4625)</h3>
                <ol>
                    {top_ips_html}
                </ol>
            </div>
            <div style="flex:1; min-width:280px;">
                <h3>Top Hedef Kullanıcı</h3>
                <ol>
                    {top_users_html}
                </ol>
            </div>
        </div>


            # brute-force mini listeler
    def li(items):
        return "".join([f"<li><code>{a}</code> — <strong>{b}</strong></li>" for a, b in items]) or "<li>Yok</li>"

    top_ips_html = li(insights["top_ips"])
    top_users_html = li(insights["top_users"])

    ww = insights["worst_window"]
    if ww["start"] and ww["end"]:
        ww_text = f"{ww['start'].strftime('%Y-%m-%d %H:%M:%S')} → {ww['end'].strftime('%Y-%m-%d %H:%M:%S')} ({insights['window_minutes']} dk pencerede {ww['count']} deneme)"
    else:
        ww_text = "Yeterli veri yok"

    alert_text = "⚠️ Brute-force şüphesi (eşik aşıldı)" if insights["alert"] else "✅ Eşik aşımı yok (brute-force sinyali zayıf)"

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
        <h2>Incident Insights</h2>
        <ul>
            {insights_html}
        </ul>

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

from collections import Counter, deque

def brute_force_insights(events, window_minutes=10, threshold=30):
    """
    4625 (failed logon) olaylarından brute force / spraying sinyali çıkarır.
    window_minutes: kayan pencere
    threshold: pencere içinde alarm eşiği
    """
    fails = [e for e in events if e.get("event_id") == "4625" and e.get("dt") and e.get("data")]
    fails.sort(key=lambda x: x["dt"])

    ip_counter = Counter()
    user_counter = Counter()
    ip_user_counter = Counter()

    # zaman penceresi analizi
    dq = deque()  # (dt, ip)
    worst_window = {"count": 0, "start": None, "end": None}

    for ev in fails:
        ip = ev["data"].get("IpAddress", "-")
        user = ev["data"].get("TargetUserName", "?")

        ip_counter[ip] += 1
        user_counter[user] += 1
        ip_user_counter[(ip, user)] += 1

        # kayan pencere: dq içine ekle
        dq.append((ev["dt"], ip))

        # pencere dışını çıkar
        window_start = ev["dt"].timestamp() - (window_minutes * 60)
        while dq and dq[0][0].timestamp() < window_start:
            dq.popleft()

        # en yoğun pencereyi yakala
        if len(dq) > worst_window["count"]:
            worst_window["count"] = len(dq)
            worst_window["end"] = ev["dt"]
            worst_window["start"] = dq[0][0]

    # alarm mı?
    alert = worst_window["count"] >= threshold

    return {
        "failed_total": len(fails),
        "top_ips": ip_counter.most_common(10),
        "top_users": user_counter.most_common(10),
        "top_ip_user": ip_user_counter.most_common(10),
        "worst_window": worst_window,
        "window_minutes": window_minutes,
        "threshold": threshold,
        "alert": alert,
    }

    out_file = generate_html_report(events, evtx_path, output_path)
    print(f"HTML rapor kaydedildi: {out_file}")


if __name__ == "__main__":
    main()
        out_file = generate_html_report(events, evtx_path, output_path)
    print(f"HTML rapor kaydedildi: {out_file}")

