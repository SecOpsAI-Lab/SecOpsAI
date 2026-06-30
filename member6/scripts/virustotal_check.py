import requests
import os
from dotenv import load_dotenv

load_dotenv('/home/kali/SecOpsAI/member6/.env')

VT_API_KEY = os.getenv('VT_API_KEY')

def check_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']
        
        print(f"VirusTotal Report for {ip_address}")
        print(f"Malicious votes: {malicious}")
        print(f"Suspicious votes: {suspicious}")
        print(f"Harmless votes: {harmless}")
        
        return {
            "ip": ip_address,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless
        }
    else:
        print(f"VirusTotal check failed: {response.status_code}")
        return None

# Test with a sample IP
result = check_virustotal("192.168.1.5")
print(result)
