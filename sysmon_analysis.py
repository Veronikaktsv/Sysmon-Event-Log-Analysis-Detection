import Evtx.Evtx as evtx
import pandas as pd
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

EVTX_FILE = "sample_data/Sysmon.evtx"

def parse_evtx(evtx_path):
    """
    Parse the EVTX file and extract relevant event data into a DataFrame.
    """
    events = []
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            xml_str = record.xml()
            root = ET.fromstring(xml_str)
            event_data = {}
            event_data['EventID'] = int(root.find('.//System/EventID').text)
            event_data['TimeCreated'] = root.find('.//System/TimeCreated').attrib['SystemTime']

            # Extract relevant fields from EventData/Data tags
            data_elems = root.findall('.//EventData/Data')
            for elem in data_elems:
                name = elem.attrib.get('Name')
                if name in ['ProcessName', 'CommandLine', 'User', 'TargetUserName', 'TargetDomainName', 'ParentImage']:
                    event_data[name] = elem.text
            events.append(event_data)
    return pd.DataFrame(events)

def detect_suspicious_events(df):
    """
    Detect suspicious events based on predefined simple rules.
    """
    alerts = []

    # Detect Privilege Escalation - Event ID 4672 (Special privileges assigned)
    privilege_escalation_events = df[df['EventID'] == 4672]
    for _, row in privilege_escalation_events.iterrows():
        user = row.get('TargetUserName', 'Unknown')
        alerts.append(f"[ALERT] Privilege escalation detected at {row['TimeCreated']} for user: {user}")

    # Detect suspicious processes from Sysmon Event ID 10 (ProcessAccess)
    process_access_events = df[df['EventID'] == 10]
    for _, row in process_access_events.iterrows():
        cmdline = row.get('CommandLine', '') or ''
        cmdline_lower = cmdline.lower()
        if 'powershell' in cmdline_lower or 'cmd.exe' in cmdline_lower:
            process_name = row.get('ProcessName', 'Unknown Process')
            alerts.append(f"[ALERT] Suspicious process execution at {row['TimeCreated']}: {process_name} CommandLine: {cmdline[:100]}")

    return alerts

def visualize_events(df):
    """
    Visualize the counts of Sysmon events by EventID using a bar chart.
    """
    plt.figure(figsize=(10,6))
    event_counts = df['EventID'].value_counts().sort_index()
    event_counts.plot(kind='bar', color='skyblue')
    plt.title("Sysmon Event Counts by Event ID")
    plt.xlabel("Event ID")
    plt.ylabel("Number of Events")
    plt.tight_layout()
    plt.show()

def main():
    print(f"Parsing EVTX file: {EVTX_FILE} ...")
    df = parse_evtx(EVTX_FILE)
    print(f"Parsed {len(df)} events successfully.\n")

    print("Detecting suspicious events...")
    alerts = detect_suspicious_events(df)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No suspicious events detected.\n")

    print("Generating event visualization...")
    visualize_events(df)

if __name__ == "__main__":
    main()
