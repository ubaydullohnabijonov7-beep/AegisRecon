# AegisRecon

**Created by Mr. H & Gemini | Kali Linux OSINT & EASM Suite**

AegisRecon is a lightweight, fast, and modular OSINT (Open Source Intelligence) and EASM (External Attack Surface Management) command-line tool built in Python 3 for security researchers, penetration testers, and SOC analysts.

## Key Features

* **Passive Subdomain & Email Discovery (`crt_recon.py`)**: Queries Certificate Transparency (CT) logs via `crt.sh` to passively enumerate subdomains and separate exposed S/MIME email addresses without touching the target infrastructure.
* **Live HTTP/HTTPS Service Probing (`http_probe.py`)**: Checks discovered subdomains for active web services, returning live HTTP status codes and server headers.
* **DNS & Email Security Posture Audit (`dns_audit.py`)**: Inspects target MX, SPF, and DMARC records to evaluate domain spoofing resilience and mail server architecture.
* **Clean Terminal UI**: Powered by `rich` for structured, color-coded security tables and status indicators.

## Installation (Kali Linux / Linux)

1. Clone the repository:
   git clone https://github.com/MR.H/AegisRecon.git
   cd AegisRecon

2. Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate

3. Install dependencies:
   pip install -r requirements.txt

## Usage

Run AegisRecon against a target domain using the `-d` (or `--domain`) flag:

    python3 -m aegisrecon.cli -d example.com

## Disclaimer

This tool is intended strictly for educational purposes, authorized security assessments, and passive reconnaissance on domains you own or have explicit permission to test.
