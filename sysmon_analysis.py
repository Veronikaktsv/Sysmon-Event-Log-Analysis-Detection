import pandas as pd
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt

XML_FILE = "sample_data/Sysmon_sample.xml"

def parse_xml(xml_path):
    events = []
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    for event in root.findall('.//Event'):
        event_data = {}
        system = event.find('System')
        event_data['EventID'] = int(system.find('EventID').text)
        event_data['TimeCreated'] = system.find('TimeCreated').attrib['SystemTime']
        
        eventdata = event.find('EventData')
        if eventdata is not None:
            for data in eventdata.findall('Data'):
                name = data.attrib.get('Name')
                if name in ['ProcessName', 'CommandLine', 'User', 'TargetUserName', 'TargetDomainName', 'ParentImage']:
                    event_data[name] = data.text
        events.append(event_data)
    
    return pd.DataFrame(events)

def detect_suspicious_events(df):
    alerts = []

    # Privilege Escalation
    pe_events = df[df['EventID'] == 4672]
    for _, row in pe_events.iterrows():
        user = row.get('TargetUserName', 'Unknown')
        alerts.append(f"[ALERT] Privilege escalation detected at {row['TimeCreated']} for user: {user}")

    # Suspicious processes (Event ID 10)
    pe10_events = df[df['EventID'] == 10]
    for _, row in pe10_events.iterrows():
        cmdline = (row.get('CommandLine') or '').lower()
        if 'powershell' in cmdline or 'cmd.exe' in cmdline:
            process = row.get('ProcessName', 'Unknown')
            alerts.append(f"[ALERT] Suspicious process execution at {row['TimeCreated']}: {process} CommandLine: {cmdline[:100]}")

    return alerts

def visualize_events(df):
    plt.figure(figsize=(10,6))
    counts = df['EventID'].value_counts().sort_index()
    counts.plot(kind='bar', color='skyblue')
    plt.title("Sysmon Event Counts by Event ID")
    plt.xlabel("Event ID")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()

def main():
    print(f"Parsing XML file: {XML_FILE}")
    df = parse_xml(XML_FILE)
    print(f"Parsed {len(df)} events.\n")

    print("Detecting suspicious events...")
    alerts = detect_suspicious_events(df)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No suspicious events detected.")

    print("\nGenerating visualization...")
    visualize_events(df)

if __name__ == "__main__":
    main()
