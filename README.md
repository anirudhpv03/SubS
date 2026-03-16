# SubS

Passive subdomain enumeration tool with DNS validation and HTTP 200 status checks.

SubS.py aggregates subdomains from multiple free, passive intelligence sources, verifies which ones resolve via DNS, and finally checks which hosts return an HTTP **200 OK** response over HTTP/HTTPS.

> Built for bug bounty hunters, pentesters, and recon enthusiasts who want a fast, no‑API‑key subdomain workflow.

---

## ✨ Features

* Passive subdomain enumeration (no brute‑force)
* Multiple public data sources
* DNS A‑record validation
* HTTP/HTTPS live check (200 status)
* Automatic redirect handling
* Clean output of live subdomains
* Simple, dependency‑light Python script

---

## 🔍 Data Sources Used

* crt.sh (Certificate Transparency)
* CertSpotter
* RapidDNS
* HackerTarget
* AlienVault OTX
* urlscan.io

All sources used are **free and passive**.

---

## 🚀 Usage

```bash
python3 subs.py example.com
```

Specify output file:

```bash
python3 subs.py example.com -o live_200.txt
```

---

## 📁 Output

* Displays:

  * Total unique subdomains found
  * DNS‑resolvable subdomains
  * Subdomains returning HTTP 200

* Saves live (200 OK) subdomains to:

  * `example.com-200.txt` (default)
  * Or custom file via `-o`

---

## 🧠 How It Works

1. Collects subdomains from multiple passive sources
2. Cleans and validates results
3. Resolves subdomains via DNS (A record)
4. Sends HTTP & HTTPS requests
5. Stores only hosts returning **200 OK**

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing only**.

Do **NOT** use against systems you do not own or have explicit permission to test.
The author is not responsible for misuse.

---

## ⭐ Credits

Created by **Anirudh PV**

If you find this useful, consider giving the repo a ⭐
