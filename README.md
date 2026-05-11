# ZeroMagenta AI Triage Tool

A Python tool that ingests Sysmon security event telemetry, uses AI to triage alerts, and automatically enriches findings with MITRE ATT&CK techniques and D3FEND defensive countermeasures.

**Status:** Active development | Current version: V5  
**Author:** Gracia V. | [zeromagenta.com](https://zeromagenta.com)

## What This Project Does

This project simulates a purple team detection workflow in an isolated Windows lab environment. Atomic Red Team is used to execute real MITRE ATT&CK techniques against a Windows 10 VM monitored by Sysmon. The resulting telemetry is exported and analyzed by a Python script that filters for suspicious activity, sends it to Google Gemini for AI-assisted triage, and enriches each finding with MITRE ATT&CK technique details and D3FEND defensive countermeasures. The final output is a structured JSON report containing severity ratings, attack narratives, recommended analyst actions, and defensive countermeasure mappings.

## Lab Environment

- **Host OS:** Windows 11
- **VM:** Windows 10 Pro (VMware Workstation Pro 17)
- **Network:** Host-Only (isolated during testing, temporarily switched to NAT for tool downloads)
- **Attack simulation:** Atomic Red Team with SwiftOnSecurity Sysmon config
- **Techniques simulated:** T1033, T1082, T1016, T1057, T1012, T1053, T1547, T1562, T1003, T1087

- ## Version History

| Version | Description |
|---------|-------------|
| V1 | Hardcoded mock alert based on Atomic Red Team T1057 output. Proved the AI triage concept end to end. |
| V2 | Dynamic input -- accepts any alert pasted into the terminal. Added error handling and modular function structure. |
| V3 | Real Sysmon telemetry ingestion. Parses Sysmon XML export, filters for suspicious activity, sends to Gemini for triage. |
| V4 | MITRE ATT&CK API enrichment via attackcti. Each identified technique automatically enriched with tactic, description, and URL. |
| V5 | D3FEND integration. Each detected technique automatically mapped to defensive countermeasures via the D3FEND REST API. |

## Tools and Technologies

| Category | Tool |
|----------|------|
| Attack simulation | Atomic Red Team |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| AI triage | Google Gemini API (gemini-2.5-flash) |
| ATT&CK enrichment | MITRE ATT&CK via attackcti library |
| Defensive mapping | MITRE D3FEND REST API |
| Scripting | Python 3.14 |
| Virtualization | VMware Workstation Pro 17 |
| OS | Windows 10 Pro (VM), Windows 11 Pro (host) |

## Setup and Usage

### Prerequisites
- Python 3.x
- Google Gemini API key (free tier available at aistudio.google.com)
- Sysmon installed on Windows VM with SwiftOnSecurity config
- Atomic Red Team installed on Windows VM

### Installation

```bash
pip install google-genai python-dotenv requests attackcti
```

### Configuration

Copy `.env.example` to `.env` and add your API key:

```bash
GEMINI_API_KEY=your_gemini_api_key_here
```

### Running the Tool

Export Sysmon events from your Windows VM:

```powershell
$events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100
$xml = "<Events>" + ($events | ForEach-Object { $_.ToXml() }) + "</Events>"
$xml | Out-File C:\sysmon-events.xml -Encoding UTF8
```

Transfer the XML file to your host machine and run:

```bash
python scripts/triage_v5.py
```

Output is printed to terminal and saved as JSON in the reports folder.

## Key Findings

Running a 10-technique attack chain across T1033, T1082, T1016, T1057, T1012, T1053, T1547, T1562, T1003, and T1087 produced the following results:

- **Overall severity:** Critical
- **Techniques identified by AI:** 11 MITRE ATT&CK techniques
- **D3FEND countermeasures mapped:** 35 for T1548, 31 for T1033, 27 for T1018
- **Tools detected:** SharpView, Seatbelt, SharpUp, SharpWatson downloaded via PowerShell
- **Blocked by Defender:** Mimikatz execution (T1059.001), Defender disable attempt (T1562)
- **Living off the land techniques:** All passed Defender undetected -- tasklist, systeminfo, whoami, reg query, netstat

**Notable finding:** The AI correctly identified QakBot recon behavior from C:\AtomicRedTeam\atomics\T1016\src\qakbot.bat and flagged the full reconnaissance chain as a coordinated attack pattern rather than isolated events.

**Open source contribution:** Identified a data gap in the attackcti library where T1548.002 (Bypass UAC) returns zero results despite existing in the official MITRE ATT&CK database. Bug report submitted to OTRF/ATTACK-Python-Client.

## Limitations and Future Work

### Current Limitations

- **Keyword-based filtering** has known detection gaps. Sophisticated attackers obfuscate commands using Base64 encoding or PowerShell aliases that bypass keyword matching entirely. Example: `whoami` can be replaced with `[System.Security.Principal.WindowsIdentity]::GetCurrent().Name` producing identical results without triggering any keyword filter.

- **Manual data transfer** is required -- Sysmon XML must be manually exported from the VM and transferred to the host machine before analysis.

- **No persistent memory** -- each run starts fresh with no awareness of previous findings or historical baselines.

### Planned Future Versions

| Version | Planned Feature |
|---------|----------------|
| V6 | Automated SOAR-inspired response playbooks executed per detected technique |
| V7 | Scheduled collection and automated Sysmon export |
| V8 | SQLite database for persistent finding storage and trend analysis |
| V9 | Web dashboard for interactive report viewing |

### Detection Engineering Note

In production environments, detection teams address keyword filter gaps through behavioral chain analysis -- flagging suspicious parent-child process relationships regardless of command content -- and ML-based anomaly detection that baselines normal activity and alerts on statistical deviations. These approaches are planned for future versions.

## Acknowledgements

- [Red Canary](https://github.com/redcanaryco/atomic-red-team) -- Atomic Red Team framework
- [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) -- Sysmon configuration
- [OTRF](https://github.com/OTRF/ATTACK-Python-Client) -- attackcti Python library
- [MITRE ATT&CK](https://attack.mitre.org) -- adversary tactics and techniques framework
- [MITRE D3FEND](https://d3fend.mitre.org) -- defensive countermeasures framework

## Contact

**Gracia V.**  
Portfolio: [zeromagenta.com](https://zeromagenta.com)
LinkedIn: [Gracia V.](https://linkedin.com/in/graciabella)
