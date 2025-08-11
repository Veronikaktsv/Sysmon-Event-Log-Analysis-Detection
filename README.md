# Sysmon-Event-Log-Analysis-Detection

This project provides a Python-based tool to parse Windows Sysmon event logs (`.evtx` files), detect suspicious activities such as privilege escalation and suspicious process executions, and visualize event distributions.

---

## Features

- Parses Sysmon `.evtx` files using the `python-evtx` library.
- Extracts key event data including:
 - `ProcessName`
 - `CommandLine`
 - `User`
 - `Event timestamps`
- Detects suspicious events with simple rules:
 - Privilege Escalation — Event ID `4672`
 - Suspicious Process Execution — Event ID `10` involving `powershell.exe` or `cmd.exe`
- Generates a bar chart of event counts by Event ID using `matplotlib`.

---
## Requirements

- Python 3.7 or higher
- Packages listed in `requirements.txt`

---

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/Veronikaktsv/Sysmon-Event-Log-Analysis-Detection.git
   cd Sysmon-Event-Log-Analysis-Detection
   
2. Install dependencies:

`pip install -r requirements.txt`

3. Add your Sysmon `.evtx` log file:
   
- Place your .evtx file inside the `sample_data/` folder.
- If you don’t have one, you can export from Windows Event Viewer:
 - Open Event Viewer (`eventvwr.msc`).
 - Navigate to:
    `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`
- Right-click Operational → Save All Events As…
- Save as:
  `sample_data/Sysmon.evtx`
(You may filter before exporting to reduce file size.)

4. Update the file path if needed:
   
In sysmon_analysis.py, verify that the EVTX_FILE variable points to your EVTX file path, e.g.:

`EVTX_FILE = "sample_data/Sysmon.evtx"`

---

## Usage

Run the analysis script:
`python sysmon_analysis.py`

The script will:
- Parse the `.evtx` file
- Detect suspicious events and print alerts in the console
- Display a bar chart showing event counts by Event ID

---

## Notes

- Event ID `4672` (Privilege Escalation) is usually found in Windows Security Logs, not Sysmon. Use Security `.evtx` logs to detect it.
- Detection rules in `detect_suspicious_events()` are basic — adjust for your environment.
- Intended for learning and demo purposes.
  For production, add:
    - Error handling
    - Log storage
    - SIEM integration
 
---

## Future Improvements
- More detection rules mapped to MITRE ATT&CK
- Export alerts to `.log` or send via Email/Slack
- Web dashboard for interactive viewing
- Real-time log ingestion

---

## License
This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## References
- [Sysmon Documentation - Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [python-evtx GitHub Repository](https://github.com/williballenthin/python-evtx)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

