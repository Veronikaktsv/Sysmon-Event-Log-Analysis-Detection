# Sysmon-Event-Log-Analysis-Detection

This project provides a Python-based tool to parse Windows Sysmon event logs (`.evtx` files), detect suspicious activities such as privilege escalation and suspicious process executions, and visualize event distributions.

---

## Features

- Parses Sysmon EVTX files using `python-evtx` library.
- Extracts key event data including ProcessName, CommandLine, User, etc.
- Detects suspicious events based on simple detection rules:
  - Privilege Escalation (Event ID 4672)
  - Suspicious Process Executions (Event ID 10) involving PowerShell or cmd.exe
- Generates bar chart visualization of event counts by Event ID.

---

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/Veronikaktsv/sysmon-event-log-analysis.git
   cd sysmon-event-log-analysis
