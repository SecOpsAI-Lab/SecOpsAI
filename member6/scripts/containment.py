import os
import subprocess
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('/home/kali/SecOpsAI/member6/.env')

def block_ip(ip_address):
    print(f"[{datetime.now()}] Initiating containment for IP: {ip_address}")
    
    try:
        # Block the IP using iptables
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"SUCCESS: IP {ip_address} has been blocked")
            log_containment(ip_address, "BLOCKED")
            return True
        else:
            print(f"FAILED: Could not block IP {ip_address}")
            print(f"Error: {result.stderr}")
            log_containment(ip_address, "FAILED")
            return False
            
    except Exception as e:
        print(f"Error during containment: {e}")
        return False

def log_containment(ip_address, status):
    log_entry = f"{datetime.now()} | IP: {ip_address} | Status: {status}\n"
    with open('/home/kali/SecOpsAI/member6/containment_log.txt', 'a') as f:
        f.write(log_entry)
    print(f"Action logged: {log_entry}")

def unblock_ip(ip_address):
    print(f"Removing block for IP: {ip_address}")
    command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    result = subprocess.run(command.split(), capture_output=True, text=True)
    if result.returncode == 0:
        print(f"IP {ip_address} unblocked successfully")
        log_containment(ip_address, "UNBLOCKED")

# Test containment with mock IP
mock_ip = "192.168.1.100"
print("Starting containment action...")
block_ip(mock_ip)
