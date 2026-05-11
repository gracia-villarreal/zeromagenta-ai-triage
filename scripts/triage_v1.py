from google import genai
import os
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()

# Initialize client
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Mock alert based on our Atomic Red Team T1057 simulation
alert = """
ALERT: Suspicious Process Discovery Activity
Time: 2026-05-09 03:47:22 UTC
Host: ZEROMAGNETA-WIN10
User: labuser
Session: Console

Process Chain:
  powershell.exe (PID 5252)
    └── cmd.exe (PID 2488)
          └── tasklist.exe (PID 6204)

Event ID: 4688 - New Process Created
Parent Process: cmd.exe
Child Process: tasklist.exe
Command Line: tasklist
Memory Usage: 9,224 K

Context: Process enumeration detected at 3AM.
Same technique repeated 3 times in 5 minutes.
"""

# Send to Gemini for triage
prompt = f"""
You are a SOC analyst triaging a security alert.
Analyze this alert and respond in exactly this format:

SEVERITY: [Critical/High/Medium/Low]
TECHNIQUE: [MITRE ATT&CK technique name and ID]
SUMMARY: [One sentence explaining what happened]
RECOMMENDED ACTION: [Specific next step for the analyst]
FALSE POSITIVE LIKELIHOOD: [High/Medium/Low - with brief reason]

Alert to analyze:
{alert}
"""

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt
)

print("=" * 60)
print("AI ALERT TRIAGE REPORT")
print("=" * 60)
print(response.text)
print("=" * 60)
