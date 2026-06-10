# Malicious IP Intelligence System

## Overview

The Malicious IP Intelligence System is a Python-based cybersecurity tool that analyzes IP addresses using threat intelligence data from AbuseIPDB and VirusTotal. It helps identify whether an IP address is Safe, Suspicious, or Malicious based on abuse reports and malware detection statistics.

## Features

* Checks IP reputation using AbuseIPDB.
* Retrieves malware detection statistics from VirusTotal.
* Classifies IPs as:

  * SAFE
  * SUSPICIOUS
  * MALICIOUS
* Displays color-coded results in the terminal.
* Generates CSV and Excel reports automatically.
* Provides a summary of detected malicious and suspicious IPs.

## Project Workflow

### Step 1: Load API Keys

The application loads API keys from a `.env` file using Python-dotenv.

### Step 2: Read IP Addresses

IP addresses are read from `ip_list.txt`.

### Step 3: Query Threat Intelligence Sources

For each IP address:

* AbuseIPDB provides abuse scores, ISP information, country, and report counts.
* VirusTotal provides malicious and suspicious detection statistics.

### Step 4: Classify the IP

Based on predefined thresholds:

* High-risk IPs are marked as **MALICIOUS**.
* Medium-risk IPs are marked as **SUSPICIOUS**.
* Low-risk IPs are marked as **SAFE**.

### Step 5: Generate Reports

Results are saved as:

* `ip_report.csv`
* `ip_report.xlsx`

### Step 6: Display Summary

The tool shows:

* Total malicious IPs
* Total suspicious IPs
* Total safe IPs
* List of detected malicious IPs

## Technologies Used

* Python
* Requests
* Pandas
* Colorama
* Python-dotenv
* AbuseIPDB API
* VirusTotal API

## Use Cases

* Security Operations Center (SOC) analysis
* Threat intelligence enrichment
* Incident response investigations
* IP reputation monitoring
* Cybersecurity learning and research
