import requests
import json
import time
import pandas as pd
from colorama import Fore, Style, init
import os
from dotenv import load_dotenv

load_dotenv()

init(autoreset=True)

#Config
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "YOUR_ABUSEIPDB_API_KEY_HERE")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
IP_FILE = "ip_list.txt"

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        data = r.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "total_reports": data.get("totalReports", 0)
        }
    except Exception as e:
        return {"abuse_score": -1, "country": "Error", "isp": str(e), "total_reports": 0}

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {"vt_malicious": malicious, "vt_suspicious": suspicious}
    except Exception as e:
        return {"vt_malicious": -1, "vt_suspicious": -1}

def classify_ip(abuse_score, vt_malicious):
    if abuse_score >= 50 or vt_malicious >= 3:
        return "MALICIOUS"
    elif abuse_score >= 10 or vt_malicious >= 1:
        return "SUSPICIOUS"
    else:
        return "SAFE"

def main():
    with open(IP_FILE) as f:
        ip_list = [line.strip() for line in f if line.strip()]

    results = []
    print(f"\n{'='*60}")
    print("       MALICIOUS IP INTELLIGENCE SYSTEM")
    print(f"{'='*60}\n")

    for ip in ip_list:
        print(f"[*] Checking: {ip}")
        abuse_data = check_abuseipdb(ip)
        vt_data = check_virustotal(ip)
        classification = classify_ip(abuse_data["abuse_score"], vt_data["vt_malicious"])

        if classification == "MALICIOUS":
            color = Fore.RED
        elif classification == "SUSPICIOUS":
            color = Fore.YELLOW
        else:
            color = Fore.GREEN

        print(color + f"    → Status: {classification} | Abuse Score: {abuse_data['abuse_score']}% | VT Malicious: {vt_data['vt_malicious']} | Country: {abuse_data['country']}")

        results.append({
            "IP": ip,
            "Classification": classification,
            "Abuse Score (%)": abuse_data["abuse_score"],
            "VT Malicious": vt_data["vt_malicious"],
            "VT Suspicious": vt_data["vt_suspicious"],
            "Country": abuse_data["country"],
            "ISP": abuse_data["isp"],
            "Total Reports": abuse_data["total_reports"]
        })
        time.sleep(1) 

    # Save results
    df = pd.DataFrame(results)
    df.to_csv("ip_report.csv", index=False)
    df.to_excel("ip_report.xlsx", index=False)

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    malicious = df[df["Classification"] == "MALICIOUS"]
    suspicious = df[df["Classification"] == "SUSPICIOUS"]
    safe = df[df["Classification"] == "SAFE"]
    print(Fore.RED    + f"  MALICIOUS  : {len(malicious)} IPs")
    print(Fore.YELLOW + f"  SUSPICIOUS : {len(suspicious)} IPs")
    print(Fore.GREEN  + f"  SAFE       : {len(safe)} IPs")
    print(f"\nReports saved: ip_report.csv and ip_report.xlsx")

    if not malicious.empty:
        print(Fore.RED + "\nMALICIOUS IPs DETECTED:")
        for _, row in malicious.iterrows():
            print(Fore.RED + f"  ⚠  {row['IP']} — {row['ISP']} ({row['Country']})")

if __name__ == "__main__":
    main()