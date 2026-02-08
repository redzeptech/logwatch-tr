# LogWatch – Windows Event Log Triage Aracı

Windows Event Log (`.evtx`) dosyalarını okuyup şüpheli aktiviteleri işaretleyen ve HTML rapor üreten Python aracı.

## Özellikler

- **python-evtx** ile `.evtx` dosyası okuma
- Aşağıdaki Event ID'lerin tespiti ve sınıflandırılması:
  - **4625** – Başarısız giriş (kritik)
  - **4624** – Gece girişi (00:00–06:00) veya RDP (Logon Type 10)
  - **4720** – Kullanıcı hesabı oluşturma (kritik)
  - **4672** – Özel yetkiler atandı (admin) (şüpheli)
  - **1102** – Denetim günlüğü silindi (kritik)
- Renkli zaman çizelgesi:
  - **Kırmızı** – Kritik
  - **Sarı** – Şüpheli
  - **Yeşil** – Normal
- Tek çıktıda özet istatistikler ve HTML rapor

## Gereksinimler

- Python 3.9+
- Windows, macOS veya Linux

## Kurulum

```bash
pip install -r requirements.txt
```

veya doğrudan:

```bash
pip install python-evtx
```

## Kullanım

Komut satırından EVTX dosya yolunu verin; araç analiz eder ve HTML rapor üretir.

```bash
python evtx_triage.py "C:\Windows\System32\winevt\Logs\Security.evtx"
```

Özel çıktı dosyası belirtmek için:

```bash
python evtx_triage.py Security.evtx -o rapor.html
```

### Argümanlar

| Argüman        | Açıklama                                      |
|----------------|-----------------------------------------------|
| `evtx_file`    | Analiz edilecek `.evtx` dosyasının yolu       |
| `-o`, `--output` | HTML rapor dosyası (varsayılan: `<dosya_adı>_report.html`) |

## Çıktı

- Konsola: bulunan olay sayısı ve kritik / şüpheli / normal dağılımı
- Dosyaya: tek sayfalık HTML rapor
  - Özet (kritik / şüpheli / normal sayıları)
  - Zaman sıralı tablo (zaman, Event ID, seviye, açıklama)
  - Renklerle vurgulanmış zaman çizelgesi

## Tespit Kuralları (Özet)

| Event ID | Koşul              | Seviye   |
|----------|--------------------|----------|
| 4625     | Başarısız giriş    | Kritik   |
| 4720     | Kullanıcı oluşturma| Kritik   |
| 1102     | Log silme          | Kritik   |
| 4624     | Gece (00–06) veya RDP girişi | Şüpheli / Normal |
| 4672     | Admin yetkisi      | Şüpheli  |

4624 için: gece girişi veya gece RDP → şüpheli; gündüz RDP veya normal giriş → normal.

## Lisans

Bu proje eğitim ve triage amaçlıdır; kullanım sorumluluğu kullanıcıya aittir.
