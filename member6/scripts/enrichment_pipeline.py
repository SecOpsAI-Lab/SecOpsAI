import requests
import os
from dotenv import load_dotenv

load_dotenv('/home/kali/SecOpsAI/member6/.env')

VT_API_KEY = os.getenv('VT_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')

# Member 5 API details
API_URL = "http://localhost:8000/detect"
API_KEY = "dev-sensor-001"

# Sample 37-feature payload
payload = {
    "dur": 100.0, "rate": 50.0, "sload": 10000.0, "dload": 5000.0,
    "spkts": 10, "dpkts": 5, "sbytes": 500.0, "dbytes": 200.0,
    "sloss": 0, "dloss": 0, "sinpkt": 50.0, "dinpkt": 30.0,
    "sjit": 10.0, "djit": 5.0, "swin": 255, "dwin": 255,
    "tcprtt": 10.0, "synack": 5.0, "ackdat": 3.0, "smean": 100.0,
    "dmean": 80.0, "trans_depth": 1, "response_body_len": 500.0,
    "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "is_ftp_login": 0,
    "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "is_sm_ips_ports": 0,
    "proto_enc": 6, "service_enc": 0, "state_enc": 2, "byte_ratio": 1.5,
    "pkt_ratio": 1.2, "total_bytes": 700.0, "jit_ratio": 2.0,
    "dur_bin_enc": 2
}

def get_detection():
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Detection API error: {response.status_code}")
            return None
    except Exception as e:
        print("Could not reach Member 5 API — check if it is running")
        return None

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

def send_slack_alert(detection, vt_result, shodan_result, src_ip):
    message = {
        "text": f"""
*SecOpsAI — Threat Detected*
*Request ID:* {detection['request_id']}
*Verdict:* {detection['verdict']}
*Latency:* {detection['latency_ms']}ms
*Source IP:* {src_ip}

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
print("Calling Member 5 detection API...")
detection = get_detection()

if detection:
    print(f"Detection result: {detection}")
    verdict = detection['verdict']
    src_ip = "192.168.1.5"  # Replace with real IP when available

    if verdict == "MALICIOUS":
        print("MALICIOUS traffic detected! Running enrichment...")
        vt_result = check_virustotal(src_ip)
        shodan_result = check_shodan(src_ip)
        send_slack_alert(detection, vt_result, shodan_result, src_ip)
    else:
        print(f"Traffic verdict: {verdict} — no alert needed")
else:
    print("Could not reach Member 5 API — check if it is running")
