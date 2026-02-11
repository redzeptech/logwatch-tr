![GitHub release](https://img.shields.io/github/v/release/redzeptech/logwatch-tr?label=version)
![License](https://img.shields.io/github/license/redzeptech/logwatch-tr)
> ⚠️ This is a triage tool, not a full forensic suite.
> 
> It helps quickly understand *what happened* before deep forensic analysis.
> Designed for analysts, sysadmins and incident responders who need fast clarity from Windows Security logs.

# LogWatch-TR

Windows Security Event Log (EVTX) triage tool


LogWatch-TR helps answer the first DFIR question:

> **“What actually happened on this machine?”**

It does not replace a SIEM.  
It accelerates the *first investigation stage*.

---

## Why this tool exists

Windows Security logs are extremely noisy.

Most investigations fail because:
every logon event is treated as human activity.

In reality:
- services log in
- scheduled tasks log in
- system accounts log in

LogWatch-TR introduces **actor classification** and isolates real user behavior.

---

## What it detects

The tool analyzes `.evtx` files and correlates authentication events:

- Failed logins — **Event ID 4625**
- Successful logons — **Event ID 4624**
- Night logins (00:00–06:00)
- RDP logins (Logon Type 10)
- New account creation — **Event ID 4720**
- Privileged logon — **Event ID 4672**
- Audit log clearing — **Event ID 1102**
- Privilege escalation correlation (4624 → 4672)

System/service noise is filtered automatically.

---

## Example Output

![Example report](docs/report.png)

The tool produces a readable **HTML timeline report** categorized as:

- 🔴 Critical
- 🟡 Suspicious
- 🟢 Normal

You can review incidents without opening Event Viewer.

---

## Download

➡️ **Latest Windows build**  
https://github.com/redzeptech/logwatch-tr/releases/latest

No installation required.

---

## Quick Start

1. Extract the zip
2. Export a `Security.evtx` file from Event Viewer
3. Put it next to the executable
4. Run:

```cmd
LogWatch-TR.exe Security.evtx

## Why I built this

During real incident investigations, I repeatedly saw analysts lose hours inside raw Event Viewer logs.

This tool was created to shorten that first step:
understanding human activity quickly and reliably.

