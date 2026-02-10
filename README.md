![GitHub release](https://img.shields.io/github/v/release/redzeptech/logwatch-tr?label=version)
![License](https://img.shields.io/github/license/redzeptech/logwatch-tr)

# LogWatch-TR
Windows Event Log (.evtx) Offline Triage & Authentication Investigation Tool

## About

**LogWatch-TR** is an offline DFIR (Digital Forensics & Incident Response) triage tool designed for blue teams and investigators.

Instead of monitoring systems like a SIEM, LogWatch-TR analyzes exported Windows Security logs and produces an investigation timeline.

When an analyst receives a `Security.evtx` file from a suspected machine, the first problem is:

> “Where should I start?”

LogWatch-TR answers that question by automatically highlighting high-risk authentication behavior and attacker indicators.

The goal is not to replace an analyst —  
it is to **reduce investigation time and false positives.**

---

## Key Capability — Human vs System Login Detection

One of the biggest problems in Windows log analysis is noise.

Windows constantly authenticates using:
- SYSTEM
- LOCAL SERVICE
- NETWORK SERVICE
- scheduled tasks
- service accounts
- computer accounts (`HOSTNAME$`)

Traditional scripts incorrectly flag these as suspicious night logins.

LogWatch-TR classifies each authentication actor into:

- `human`
- `local_builtin`
- `service/system`
- `machine`
- `unknown`

Night login alerts are triggered **only for real users**, not Windows background activity.

This dramatically reduces false positives and allows analysts to immediately focus on attacker behavior.

---

## What It Detects

The tool analyzes high-value Windows Security Event IDs:

| Event ID | Meaning | Why important |
|--------|------|------|
| 4625 | Failed logon | Brute-force / password spraying indicator |
| 4624 | Successful logon | Lateral movement / account access |
| 4720 | User created | Persistence / backdoor account |
| 4672 | Special privileges assigned | Privilege escalation indicator |
| 1102 | Audit log cleared | Anti-forensics activity |

Additional heuristics:
- Night logins (00:00–06:00)
- Night RDP sessions
- Brute-force attempt detection
- Privilege escalation correlation (4624 → 4672)

---

## Output

LogWatch-TR generates a static HTML report including:

- chronological timeline
- severity color coding
- suspicious authentication events
- brute-force patterns
- log clearing alerts
- investigation insights

The report is designed to be shared with investigators or management without requiring a SIEM.

---

## What LogWatch-TR is NOT

LogWatch-TR is **not a SIEM** and does not:
- monitor endpoints
- collect logs continuously
- generate real-time alerts
- store telemetry

It is an **offline investigation triage tool**.

---

## Installation

Requires Python 3.10+

```bash
git clone https://github.com/redzeptech/logwatch-tr.git
cd logwatch-tr
pip install python-evtx
