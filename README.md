![GitHub release](https://img.shields.io/github/v/release/redzeptech/logwatch-tr?label=version)
![License](https://img.shields.io/github/license/redzeptech/logwatch-tr)

# LogWatch-TR
Windows Event Log (.evtx) Triage and Suspicious Activity Reporting Tool

LogWatch-TR is a lightweight digital forensics triage tool that parses Windows Security Event Logs and highlights potentially suspicious activities.  
The goal is not to replace an analyst, but to accelerate the initial review phase.

## Features

The tool automatically analyzes .evtx files and detects:

- Failed login attempts (Event ID 4625)
- Night logins (00:00-06:00)
- RDP logins (Logon Type 10)
- New user account creation (Event ID 4720)
- Privileged logons (Event ID 4672)
- Audit log clearing attempts (Event ID 1102)

The output is a readable **HTML timeline report** categorized as:
- 🔴 Critical
- 🟡 Suspicious
- 🟢 Normal
- Filters Windows service logons (reduces false positives)

---

## Installation

Requires Python 3.10+

Clone repository:

```bash
git clone https://github.com/redzeptech/logwatch-tr.git
cd logwatch-tr
## Contributing

This project is intentionally kept simple to serve as a starting point for DFIR triage automation.

Ideas and improvements are welcome:
- additional EventID detections
- brute-force correlation
- visualization improvements
- export formats

Feel free to fork, improve, and open a pull request.


