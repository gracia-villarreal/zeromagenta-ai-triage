from google import genai
import os
import json
import xml.etree.ElementTree as ET
import requests
from datetime import datetime
from dotenv import load_dotenv
from attackcti import attack_client

# Load API key
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def parse_sysmon_xml(filepath):
    """Parse Sysmon XML file and extract event fields."""
    events = []
    
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as e:
        print(f"ERROR: Could not parse XML file. Reason: {str(e)}")
        return events

    namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    for event in root:
        try:
            # Extract core fields
            system = event.find('ns:System', namespace)
            event_data = event.find('ns:EventData', namespace)

            if system is None:
                continue

            event_id = system.find('ns:EventID', namespace)
            time_created = system.find('ns:TimeCreated', namespace)

            event_dict = {
                'event_id': event_id.text if event_id is not None else 'Unknown',
                'time': time_created.get('SystemTime', 'Unknown') if time_created is not None else 'Unknown',
                'fields': {}
            }

            # Extract all event data fields
            if event_data is not None:
                for data in event_data:
                    name = data.get('Name', '')
                    value = data.text or ''
                    if name:
                        event_dict['fields'][name] = value

            events.append(event_dict)

        except Exception as e:
            continue

    return events


def group_events(events):
    """Group events by type for analysis."""
    groups = {
        'process_creation': [],
        'file_creation': [],
        'registry_changes': [],
        'network_connections': [],
        'other': []
    }

    for event in events:
        eid = event['event_id']
        if eid == '1':
            groups['process_creation'].append(event)
        elif eid == '11':
            groups['file_creation'].append(event)
        elif eid == '13':
            groups['registry_changes'].append(event)
        elif eid == '3':
            groups['network_connections'].append(event)
        else:
            groups['other'].append(event)

    return groups


def format_events_for_ai(groups):
    """Format grouped events into a readable summary for Gemini."""
    summary = []

    if groups['process_creation']:
        summary.append("=== PROCESS CREATION EVENTS (Sysmon ID 1) ===")
        found = 0
        for e in groups['process_creation']:
            f = e['fields']
            cmdline = f.get('CommandLine', '').lower()
            suspicious_keywords = ['whoami', 'tasklist', 'systeminfo',
                                   'reg query', 'schtasks', 'net user',
                                   'netstat', 'ipconfig', 'wmic',
                                   'quser', 'arp', 'route', 'findstr',
                                   'nslookup', 'nltest', 'bcdedit']
            if not any(k in cmdline for k in suspicious_keywords):
                continue
            summary.append(f"Time: {e['time']}")
            summary.append(f"  Image: {f.get('Image', 'N/A')}")
            summary.append(f"  CommandLine: {f.get('CommandLine', 'N/A')}")
            summary.append(f"  ParentImage: {f.get('ParentImage', 'N/A')}")
            summary.append(f"  ParentCommandLine: {f.get('ParentCommandLine', 'N/A')}")
            summary.append(f"  User: {f.get('User', 'N/A')}")
            summary.append("")
            found += 1
        summary.append(f"Total suspicious process events found: {found}")

    if groups['file_creation']:
        summary.append("=== FILE CREATION EVENTS (Sysmon ID 11) ===")
        for e in groups['file_creation'][:10]:
            f = e['fields']
            summary.append(f"Time: {e['time']}")
            summary.append(f"  TargetFilename: {f.get('TargetFilename', 'N/A')}")
            summary.append(f"  Image: {f.get('Image', 'N/A')}")
            summary.append("")

    if groups['registry_changes']:
        summary.append("=== REGISTRY MODIFICATION EVENTS (Sysmon ID 13) ===")
        for e in groups['registry_changes'][:10]:
            f = e['fields']
            summary.append(f"Time: {e['time']}")
            summary.append(f"  TargetObject: {f.get('TargetObject', 'N/A')}")
            summary.append(f"  Image: {f.get('Image', 'N/A')}")
            summary.append("")

    return "\n".join(summary)


def triage_with_ai(formatted_events):
    """Send formatted events to Gemini for triage."""
    
    prompt = f"""
You are a senior SOC analyst reviewing Sysmon telemetry from a Windows endpoint.
Analyze these security events and identify suspicious activity.

Respond in exactly this format:

OVERALL_SEVERITY: [Critical/High/Medium/Low]
ATTACK_STAGE: [What stage of the attack lifecycle this represents]
SUSPICIOUS_FINDINGS:
  - [Finding 1 with specific evidence]
  - [Finding 2 with specific evidence]
  - [Finding 3 with specific evidence]
MITRE_TECHNIQUES:
  - [Technique ID]: [Technique Name] - [Brief reason]
  - [Technique ID]: [Technique Name] - [Brief reason]
ATTACK_NARRATIVE: [2-3 sentences describing what an attacker was doing]
RECOMMENDED_ACTIONS:
  - [Action 1]
  - [Action 2]
  - [Action 3]

Sysmon Events to analyze:
{formatted_events}
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"ERROR: AI triage failed. Reason: {str(e)}"


def enrich_with_mitre(triage_text):
    """Extract technique IDs from AI output and enrich with MITRE ATT&CK data."""
    import re
    
    print("\nConnecting to MITRE ATT&CK database...")
    
    try:
        client = attack_client()
    except Exception as e:
        return {"error": f"Could not connect to MITRE ATT&CK: {str(e)}"}
    
    # Extract technique IDs from AI triage output
    technique_ids = re.findall(r'T\d{4}(?:\.\d{3})?', triage_text)
    technique_ids = list(set(technique_ids))  # remove duplicates
    
    print(f"Found {len(technique_ids)} unique techniques: {technique_ids}")
    
    enriched = {}
    
    # Get all techniques once then filter
    print("Fetching all MITRE ATT&CK techniques...")
    all_techniques = client.get_techniques(include_subtechniques=True)
    
    # Build lookup by external ID
    tech_lookup = {}
    for t in all_techniques:
        for ref in t.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tech_lookup[ref.get('external_id')] = t

    for tech_id in technique_ids:
        try:
            t = tech_lookup.get(tech_id)
            if t:
                enriched[tech_id] = {
                    "name": t.get("name", "Unknown"),
                    "description": t.get("description", "")[:300] + "...",
                    "tactic": [p.get("phase_name", "") for p in t.get("kill_chain_phases", [])],
                    "detection": t.get("x_mitre_detection", "No detection guidance available")[:300] + "...",
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                }
                print(f"  Enriched: {tech_id} - {enriched[tech_id]['name']}")
            else:
                enriched[tech_id] = {"error": "Technique not found"}
        except Exception as e:
            enriched[tech_id] = {"error": str(e)}
    
    return enriched


def enrich_with_d3fend(technique_ids):
    """Query D3FEND API for defensive countermeasures for each technique."""
    print("\nQuerying MITRE D3FEND for defensive countermeasures...")
    d3fend_results = {}

    for tech_id in technique_ids:
        try:
            # Try sub-technique first, fall back to parent
            lookup_id = tech_id
            url = f"https://d3fend.mitre.org/api/offensive-technique/attack/{lookup_id}.json"
            response = requests.get(url, timeout=10)

            # Fall back to parent technique if sub-technique returns nothing
            if response.status_code != 200 and '.' in tech_id:
                lookup_id = tech_id.split('.')[0]
                url = f"https://d3fend.mitre.org/api/offensive-technique/attack/{lookup_id}.json"
                response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                bindings = data.get('off_to_def', {}).get('results', {}).get('bindings', [])

                if bindings:
                    # Group countermeasures by tactic
                    grouped = {}
                    seen = set()

                    for b in bindings:
                        def_tech = b.get('def_tech_label', {}).get('value', '')
                        def_tactic = b.get('def_tactic_label', {}).get('value', '').upper()
                        def_id = b.get('def_tech_id', {}).get('value', '')
                        def_artifact = b.get('def_artifact_label', {}).get('value', '')

                        if def_tech and def_tech not in seen:
                            seen.add(def_tech)
                            if def_tactic not in grouped:
                                grouped[def_tactic] = []
                            grouped[def_tactic].append({
                                "technique": def_tech,
                                "d3fend_id": def_id,
                                "artifact": def_artifact,
                                "url": f"https://d3fend.mitre.org/technique/d3f:{def_tech.replace(' ', '-')}/"
                            })

                    d3fend_results[tech_id] = {
                        "grouped_countermeasures": grouped,
                        "total_countermeasures": len(seen),
                        "lookup_id_used": lookup_id,
                        "d3fend_url": f"https://d3fend.mitre.org/offensive-technique/attack/{lookup_id}/"
                    }
                    print(f"  {tech_id}: {len(seen)} countermeasures found across {len(grouped)} tactics")
                else:
                    d3fend_results[tech_id] = {"error": "No D3FEND mappings found"}
            else:
                d3fend_results[tech_id] = {"error": f"API returned {response.status_code}"}

        except Exception as e:
            d3fend_results[tech_id] = {"error": str(e)}

    return d3fend_results


def save_report(triage_result, groups, mitre_enrichment, d3fend_enrichment):
    """Save the triage report as JSON."""
    
    report = {
        "report_generated": datetime.now().isoformat(),
        "report_version": "v6",
        "tool": "ZeroMagenta AI Triage Tool",
        "event_summary": {
            "process_creation_count": len(groups['process_creation']),
            "file_creation_count": len(groups['file_creation']),
            "registry_changes_count": len(groups['registry_changes']),
            "network_connections_count": len(groups['network_connections'])
        },
        "ai_triage": triage_result,
        "mitre_enrichment": mitre_enrichment,
        "d3fend_enrichment": d3fend_enrichment
    }

    output_path = "D:\\ZeroMagenta-Labs\\Reports\\triage_v6_report.json"
    
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {output_path}")
    except Exception as e:
        print(f"ERROR: Could not save report. Reason: {str(e)}")

    return report


def main():
    print("=" * 60)
    print("ZEROMAGNETA AI TRIAGE TOOL v6")
    print("Sysmon Telemetry Ingestion + AI Analysis + MITRE Enrichment")
    print("=" * 60)

    # Path to Sysmon XML
    xml_path = "D:\\ZeroMagenta-Labs\\Scripts\\sysmon-all-attacks.xml"

    print(f"\nLoading Sysmon events from: {xml_path}")
    events = parse_sysmon_xml(xml_path)

    if not events:
        print("ERROR: No events found. Check the XML file path.")
        return

    print(f"Loaded {len(events)} events successfully.")

    # Group events by type
    groups = group_events(events)
    print(f"\nEvent breakdown:")
    print(f"  Process Creation (ID 1):  {len(groups['process_creation'])}")
    print(f"  File Creation (ID 11):    {len(groups['file_creation'])}")
    print(f"  Registry Changes (ID 13): {len(groups['registry_changes'])}")
    print(f"  Network Connections (ID 3): {len(groups['network_connections'])}")

    # Format for AI
    print("\nFormatting events for AI analysis...")
    formatted = format_events_for_ai(groups)

    # Send to Gemini
    print("Sending to Gemini for triage...")
    triage_result = triage_with_ai(formatted)

    # Display result
    print("\n" + "=" * 60)
    print("AI TRIAGE REPORT")
    print("=" * 60)
    print(triage_result)

   # Enrich with MITRE ATT&CK
    mitre_enrichment = enrich_with_mitre(triage_result)
    
    # Display enrichment summary
    print("\n" + "=" * 60)
    print("MITRE ATT&CK ENRICHMENT")
    print("=" * 60)
    for tech_id, details in mitre_enrichment.items():
        if "error" not in details:
            print(f"\n{tech_id}: {details['name']}")
            print(f"  Tactic: {', '.join(details['tactic'])}")
            print(f"  URL: {details['url']}")

    # D3FEND defensive countermeasures
    d3fend_enrichment = enrich_with_d3fend(list(mitre_enrichment.keys()))

    print("\n" + "=" * 60)
    print("D3FEND DEFENSIVE COUNTERMEASURES")
    print("=" * 60)
    for tech_id, details in d3fend_enrichment.items():
        if "error" not in details:
            print(f"\n{tech_id} — {details['total_countermeasures']} total countermeasures")
            print(f"  Reference: {details['d3fend_url']}")
            for tactic, measures in details['grouped_countermeasures'].items():
                print(f"\n  [{tactic}]")
                for m in measures:
                    print(f"    {m['technique']}")
                    if m['url']:
                        print(f"    {m['url']}")

    # Save JSON report
    save_report(triage_result, groups, mitre_enrichment, d3fend_enrichment)


if __name__ == "__main__":
    main()