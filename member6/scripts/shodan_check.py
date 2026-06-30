import requests
import os
from dotenv import load_dotenv

load_dotenv('/home/kali/SecOpsAI/member6/.env')

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

def check_shodan(ip_address):
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        
        print(f"Shodan Report for {ip_address}")
        print(f"Organization: {data.get('org', 'Unknown')}")
        print(f"Country: {data.get('country_name', 'Unknown')}")
        print(f"Open Ports: {data.get('ports', [])}")
        print(f"Hostnames: {data.get('hostnames', [])}")
        
        return {
            "ip": ip_address,
            "org": data.get('org', 'Unknown'),
            "country": data.get('country_name', 'Unknown'),
            "ports": data.get('ports', []),
            "hostnames": data.get('hostnames', [])
        }
    elif response.status_code == 404:
        print(f"IP {ip_address} not found in Shodan database")
        return {
            "ip": ip_address,
            "org": "Unknown",
            "country": "Unknown", 
            "ports": [],
            "hostnames": []
        }
    else:
        print(f"Shodan check failed: {response.status_code}")
        return None

# Test with a sample IP
result = check_shodan("8.8.8.8")
print(result)
