import requests
import json
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv('/home/kali/SecOpsAI/member6/.env')

SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')

def send_slack_alert(alert_data):
    message = {
        "text": f"""
*SecOpsAI Alert Detected*
*Threat Type:* {alert_data['threat_type']}
*Source IP:* {alert_data['src_ip']}
*Confidence:* {alert_data['confidence']}
*Severity:* {alert_data['severity']}
        """
    }
    response = requests.post(SLACK_WEBHOOK_URL, json=message)
    if response.status_code == 200:
        print("Alert sent to Slack successfully")
    else:
        print(f"Failed to send alert: {response.status_code}")

# Test alert
alert_data = {
    "threat_type": "C2 Beaconing",
    "src_ip": "192.168.1.5",
    "confidence": "94%",
    "severity": "HIGH"
}

send_slack_alert(alert_data)
