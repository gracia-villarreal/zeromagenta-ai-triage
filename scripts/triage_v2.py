from google import genai
import os
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def triage_alert(alert_text):
    """Send any alert text to Gemini for AI triage."""
    
    prompt = f"""
You are a SOC analyst triaging a security alert.
Analyze this alert and respond in exactly this format:

SEVERITY: [Critical/High/Medium/Low]
TECHNIQUE: [MITRE ATT&CK technique name and ID]
SUMMARY: [One sentence explaining what happened]
RECOMMENDED ACTION: [Specific next step for the analyst]
FALSE POSITIVE LIKELIHOOD: [High/Medium/Low - with brief reason]

Alert to analyze:
{alert_text}
"""
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text
    
    except Exception as e:
        return f"ERROR: Could not complete triage. Reason: {str(e)}"


def main():
    print("=" * 60)
    print("ZEROMAGNETA AI ALERT TRIAGE TOOL v2")
    print("=" * 60)
    print("Paste your alert below.")
    print("When done, type END on a new line and press Enter.")
    print("=" * 60)
    
    # Collect multi-line input from user
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    
    alert_text = "\n".join(lines)
    
    if not alert_text.strip():
        print("ERROR: No alert data provided.")
        return
    
    print("\nAnalyzing alert...")
    result = triage_alert(alert_text)
    
    print("\n" + "=" * 60)
    print("AI TRIAGE REPORT")
    print("=" * 60)
    print(result)
    print("=" * 60)


if __name__ == "__main__":
    main()
