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

3. Add your Sysmon .evtx log file:
   
Place your Sysmon EVTX file inside the sample_data/ folder.

If you don’t have a sample EVTX file, follow these steps to export one from Windows Event Viewer:

- Open Event Viewer (eventvwr.msc).
- Navigate to: Applications and Services Logs → Microsoft → Windows → Sysmon → Operational.
- Right-click on Operational and select Save All Events As...
- Save the log as Sysmon.evtx inside the sample_data/ folder.
- You can filter the log for a smaller size before exporting if needed.

4. Update the file path if needed:
   
In sysmon_analysis.py, verify that the EVTX_FILE variable points to your EVTX file path, e.g.:

`EVTX_FILE = "sample_data/Sysmon.evtx"`

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
This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

## References
- [Sysmon Documentation - Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [python-evtx GitHub Repository](https://github.com/williballenthin/python-evtx)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

