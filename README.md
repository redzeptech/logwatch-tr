![GitHub release](https://img.shields.io/github/v/release/redzeptech/logwatch-tr?label=version)
![License](https://img.shields.io/github/license/redzeptech/logwatch-tr)

# LogWatch-TR

Offline Windows Security.evtx triage tool that analyzes authentication activity and highlights real user behavior instead of system noise.

LogWatch-TR is a lightweight DFIR (Digital Forensics & Incident Response) utility designed to help analysts quickly review Windows Security Event Logs and focus on meaningful activity.

The tool does **not** try to replace a SIEM.  
Its purpose is to accelerate the first investigation stage: *“What actually happened on this machine?”*

---

## What Makes It Different

Windows Security logs are extremely noisy.  
Most detections fail because they treat every logon event as if a human performed it.

LogWatch-TR introduces **actor classification**:

It automatically distinguishes:
- human users
- local built-in accounts
- service accounts
- machine/computer accounts

This dramatically reduces false positives and allows real suspicious behavior to stand out.

Examples:
- SYSTEM logons are not flagged as suspicious
- Scheduled task/service activity is filtered
- Only meaningful human logins are evaluated for alerts

---

## Detection Capabilities

The tool analyzes `.evtx` files and correlates important authentication events:

- Failed login attempts — **Event ID 4625**
- Successful logons — **Event ID 4624**
- Night logins (00:00-06:00)
- RDP logins (Logon Type 10)
- New user account creation — **Event ID 4720**
- Privileged logon — **Event ID 4672**
- Audit log clearing — **Event ID 1102**
- Possible privilege escalation (4624 → 4672 correlation)

Human-only filtering is applied to suspicious login detection to prevent system/service false positives.

---

## Output

LogWatch-TR generates a readable **HTML timeline report**.

Events are categorized:

- 🔴 Critical
- 🟡 Suspicious
- 🟢 Normal

The report allows quick triage without opening Event Viewer.

---

## Installation

Requires **Python 3.10+**

Clone repository:

```bash
git clone https://github.com/redzeptech/logwatch-tr.git
cd logwatch-tr
pip install python-evtx
