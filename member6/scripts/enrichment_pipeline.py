import requests
import os
from dotenv import load_dotenv

load_dotenv('/home/kali/SecOpsAI/member6/.env')

VT_API_KEY = os.getenv('VT_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')

# Mock detection from Member 5 API (replace with real API URL when ready)
mock_detection = {
    "alert": True,
    "confidence": 0.94,
    "threat_type": "C2 Beaconing",
    "src_ip": "8.8.8.8",
    "severity": "HIGH"
}

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        return {"malicious": stats['malicious'], "suspicious": stats['suspicious'], "harmless": stats['harmless']}
    return {"malicious": "N/A", "suspicious": "N/A", "harmless": "N/A"}

def check_shodan(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {"org": data.get('org', 'Unknown'), "country": data.get('country_name', 'Unknown'), "ports": data.get('ports', [])}
    return {"org": "Unknown", "country": "Unknown", "ports": []}

def send_slack_alert(detection, vt_result, shodan_result):
    message = {
        "text": f"""
*SecOpsAI — Threat Detected*
*Threat Type:* {detection['threat_type']}
*Source IP:* {detection['src_ip']}
*Confidence:* {detection['confidence']}
*Severity:* {detection['severity']}

*VirusTotal Report*
Malicious: {vt_result['malicious']} | Suspicious: {vt_result['suspicious']} | Harmless: {vt_result['harmless']}

*Shodan Report*
Organization: {shodan_result['org']}
Country: {shodan_result['country']}
Open Ports: {shodan_result['ports']}
        """
    }
    response = requests.post(SLACK_WEBHOOK_URL, json=message)
    if response.status_code == 200:
        print("Full enriched alert sent to Slack successfully")
    else:
        print(f"Slack alert failed: {response.status_code}")

# Run the pipeline
print("Starting enrichment pipeline...")
print(f"Detection received: {mock_detection['threat_type']} from {mock_detection['src_ip']}")

print("Checking VirusTotal...")
vt_result = check_virustotal(mock_detection['src_ip'])
print(f"VirusTotal done: {vt_result}")

print("Checking Shodan...")
shodan_result = check_shodan(mock_detection['src_ip'])
print(f"Shodan done: {shodan_result}")

print("Sending to Slack...")
send_slack_alert(mock_detection, vt_result, shodan_result)
