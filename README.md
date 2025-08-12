# Sysmon-Event-Log-Analysis-Detection (XML)

This project provides a Python-based tool to parse Windows Sysmon event logs exported in XML format, detect suspicious activities such as privilege escalation and suspicious process executions, and visualize event distributions.

---

## Features

- Parses Sysmon event logs in XML format.
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

   ```bash
   pip install -r requirements.txt

3. Add your Sysmon event log in XML format:
   
- Place your exported XML log inside the `sample_data/` folder named `Sysmon_sample.xml`.
- You can export from Windows Event Viewer:
 - Open Event Viewer (`eventvwr.msc`).
 - Navigate to:
    `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`
- Right-click Operational → Save All Events As…
- Choose XML format and save as `sample_data/Sysmon_sample.xml`

4. Verify the XML file path in sysmon_analysis.py:

`XML_FILE = "sample_data/Sysmon_sample.xml"`

---

## Usage

Run the analysis script:
`python sysmon_analysis.py`

The script will:
- Parse the XML file
- Detect suspicious events and print alerts in the console
- Display a bar chart showing event counts by Event ID

---

## Notes

- Event ID `4672` (Privilege Escalation) is typically found in Windows Security logs, not Sysmon logs. Use Security XML logs to detect this event.
- Detection rules in `detect_suspicious_events()` are basic and for demonstration — customize them for your environment.
- Intended for learning and demo purposes only.
  For production, consider:
    - Robust error handling
    - Persistent log storage
    - SIEM integration
 
---

## Future Improvements
- Add more detection rules mapped to MITRE ATT&CK framework
- Export alerts to `.log` or send via Email/Slack
- Develop a web dashboard for interactive viewing
- Support Real-time log ingestion and alerting

---

## License
This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## References
- [Sysmon Documentation - Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

