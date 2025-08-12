import pandas as pd
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

XML_FILE = "sample_data/Sysmon_sample.xml"

def parse_xml(xml_path):
    events = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Namespace might be present in exported XML, handle it
    ns = {'ns': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

    for event in root.findall('.//ns:Event' if ns else './/Event', ns):
        event_data = {}
        system = event.find('ns:System' if ns else 'System', ns)
        if system is None:
            continue

        event_id_elem = system.find('ns:EventID' if ns else 'EventID', ns)
        time_created_elem = system.find('ns:TimeCreated' if ns else 'TimeCreated', ns)
        if event_id_elem is None or time_created_elem is None:
            continue

        event_data['EventID'] = int(event_id_elem.text)
        event_data['TimeCreated'] = time_created_elem.attrib.get('SystemTime', '')

        eventdata = event.find('ns:EventData' if ns else 'EventData', ns)
        if eventdata is not None:
            for data in eventdata.findall('ns:Data' if ns else 'Data', ns):
                name = data.attrib.get('Name')
                if name in ['ProcessName', 'CommandLine', 'User', 'TargetUserName', 'TargetDomainName', 'ParentImage']:
                    event_data[name] = data.text
        events.append(event_data)

    return pd.DataFrame(events)

def detect_suspicious_events(df):
    alerts = []

    # Privilege Escalation (Event ID 4672)
    pe_events = df[df['EventID'] == 4672]
    for _, row in pe_events.iterrows():
        user = row.get('TargetUserName', 'Unknown')
        alerts.append(f"[ALERT] Privilege escalation detected at {row['TimeCreated']} for user: {user}")

    # Suspicious Process Execution (Event ID 10)
    suspicious_events = df[df['EventID'] == 10]
    for _, row in suspicious_events.iterrows():
        cmdline = (row.get('CommandLine') or '').lower()
        if 'powershell' in cmdline or 'cmd.exe' in cmdline:
            process = row.get('ProcessName', 'Unknown')
            alerts.append(f"[ALERT] Suspicious process execution at {row['TimeCreated']}: {process} CommandLine: {cmdline[:100]}")

    return alerts

def visualize_events(df):
    plt.figure(figsize=(10, 6))
    event_counts = df['EventID'].value_counts().sort_index()
    event_counts.plot(kind='bar', color='skyblue')
    plt.title("Sysmon Event Counts by Event ID")
    plt.xlabel("Event ID")
    plt.ylabel("Number of Events")
    plt.tight_layout()
    plt.show()

def main():
    print(f"Parsing XML file: {XML_FILE} ...")
    df = parse_xml(XML_FILE)
    print(f"Parsed {len(df)} events.\n")

    print("Detecting suspicious events...")
    alerts = detect_suspicious_events(df)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No suspicious events detected.")

    print("\nGenerating event visualization...")
    visualize_events(df)

if __name__ == "__main__":
    main()
