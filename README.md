# Sysmon-Event-Log-Analysis-Detection

This project provides a Python-based tool to parse Windows Sysmon event logs (`.evtx` files), detect suspicious activities such as privilege escalation and suspicious process executions, and visualize event distributions.

---

## Features

- Parses Sysmon EVTX files using the [`python-evtx`](https://github.com/williballenthin/python-evtx) library.
- Extracts key event data including `ProcessName`, `CommandLine`, `User`, and more.
- Detects suspicious events based on simple detection rules:
  - Privilege Escalation (Event ID 4672)
  - Suspicious Process Executions (Event ID 10) involving PowerShell or cmd.exe
- Generates bar chart visualization of event counts by Event ID using `matplotlib`.

---

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/Veronikaktsv/sysmon-event-log-analysis.git
   cd sysmon-event-log-analysis
   
2. Install dependencies:

`pip install -r requirements.txt`

4. Add your Sysmon .evtx log file:

`Place your Sysmon EVTX file inside the sample_data/ folder and update the EVTX_FILE path in sysmon_analysis.py if necessary.`

---

## Usage

Run the analysis script:
`python sysmon_analysis.py`

The script will:
- Parse the EVTX file
- Detect suspicious events and print alerts in the console
- Display a bar chart showing event counts by Event ID

---

## Notes
- Event ID 4672 (Privilege Escalation) is typically found in Windows Security logs, not Sysmon logs. To detect these events, use Security EVTX logs.
- Modify detection rules in detect_suspicious_events() to tailor the tool to your environment.
- This is a basic tool meant for learning and demonstration. For production use, consider more robust error handling and integration with SIEM platforms.

---

## Future Improvements
- Add more detection rules aligned with MITRE ATT&CK framework.
- Export alerts to log files or send notifications via email/slack.
- Develop a web-based dashboard for interactive event exploration.
- Support real-time log ingestion and analysis.

---

## License
This project is licensed under the MIT License - see the @LICENSE file for details.

## References
- Sysmon Documentation - Microsoft
- python-evtx GitHub Repository
- MITRE ATT&CK Framework

## Author
Veronika Katsevych - Veronikaktsv
