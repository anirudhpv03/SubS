#!/usr/bin/env python3
import sys
import requests
import dns.resolver
import time
import re
import argparse

# Silence SSL warnings
requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (SubS.py)"
}

TIMEOUT = 8

# ---------------- VALIDATION ---------------- #

def is_valid_subdomain(sub, domain):
    sub = sub.lower().strip()

    if not sub:
        return False
    if sub.startswith(("http://", "https://")):
        return False
    if "*" in sub:
        return False
    if not sub.endswith("." + domain):
        return False
    if sub.count(domain) != 1:
        return False
    return True

# ---------------- HTTP 200 CHECK ---------------- #

def check_url_200(host):
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{host}",
                headers=HEADERS,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True
            )
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
    return False

# ---------------- ENUMERATOR ---------------- #

class SubSpy:
    def __init__(self, domain, timeout=25, output=None):
        self.domain = domain
        self.timeout = timeout
        self.output = output or f"{domain}-200.txt"

        self.all_found = set()
        self.dns_live = set()
        self.live_200 = []

    def banner(self):
        print("""
╔═══════════════════════════════════════════╗
║               SUBS.PY                     ║
║   Passive Subdomain Enum + CHECK200       ║
╚═══════════════════════════════════════════╝
""")
        print(f"[*] Target Domain: {self.domain}\n")

    def _add(self, sub):
        if is_valid_subdomain(sub, self.domain):
            self.all_found.add(sub)

    # ---------------- SOURCES ---------------- #

    def crtsh_enum(self):
        print("[+] crt.sh")
        url = f"http://crt.sh/?q=%.{self.domain}&output=json"
        try:
            r = requests.get(url, headers=HEADERS, timeout=self.timeout)
            for e in r.json():
                for sub in e.get("name_value", "").split("\n"):
                    self._add(sub.replace("*.", ""))
            print("    [✓] done")
        except:
            print("    [✗] failed")

    def certspotter_enum(self):
        print("[+] CertSpotter")
        try:
            url = (
                "https://api.certspotter.com/v1/issuances"
                f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
            )
            r = requests.get(url, headers=HEADERS, timeout=self.timeout)
            for entry in r.json():
                for sub in entry.get("dns_names", []):
                    self._add(sub)
            print("    [✓] done")
        except:
            print("    [✗] failed")

    def rapiddns_enum(self):
        print("[+] RapidDNS")
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            r = requests.get(url, headers=HEADERS, timeout=self.timeout)
            subs = set(re.findall(rf"[\\w.-]+\\.{re.escape(self.domain)}", r.text))
            for sub in subs:
                self._add(sub)
            print("    [✓] done")
        except:
            print("    [✗] failed")



    def hackertarget_enum(self):
        print("[+] HackerTarget")
        try:
            r = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                headers=HEADERS,
                timeout=self.timeout
            )
            for line in r.text.splitlines():
                if "," in line:
                    self._add(line.split(",")[0])
            print("    [✓] done")
        except:
            print("    [✗] failed")

    def alienvault_enum(self):
        print("[+] AlienVault OTX")
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                headers=HEADERS,
                timeout=self.timeout
            )
            for e in r.json().get("passive_dns", []):
                self._add(e.get("hostname", ""))
            print("    [✓] done")
        except:
            print("    [✗] failed")

    def urlscan_enum(self):
        print("[+] urlscan.io")
        try:
            r = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}",
                headers=HEADERS,
                timeout=self.timeout
            )
            for res in r.json().get("results", []):
                self._add(res.get("page", {}).get("domain", ""))
            print("    [✓] done")
        except:
            print("    [✗] failed")

    # ---------------- DNS ---------------- #

    def verify_dns(self):
        print("\n[+] DNS resolution")
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = 3

        for sub in sorted(self.all_found):
            try:
                resolver.resolve(sub, "A")
                self.dns_live.add(sub)
                print(f"[✓] {sub}")
            except:
                pass

        print(f"\n[✓] DNS-live: {len(self.dns_live)}")

    # ---------------- CHECK200 ---------------- #

    def check_200(self):
        print("\n[+] HTTP 200 check\n")

        for sub in sorted(self.dns_live):
            if check_url_200(sub):
                self.live_200.append(sub)
                print(f"[200] {sub}")

        print("\n========== SUMMARY ==========")
        print(f"Total checked : {len(self.dns_live)}")
        print(f"Live (200)    : {len(self.live_200)}")

    # ---------------- OUTPUT ---------------- #

    def save_results(self):
        if not self.live_200:
            return

        with open(self.output, "w") as f:
            for sub in self.live_200:
                f.write(sub + "\n")

        print(f"\n[+] Saved to {self.output}")

    # ---------------- RUN ---------------- #

    def run(self):
        self.banner()

        self.crtsh_enum()
        self.certspotter_enum()
        self.rapiddns_enum()
        self.hackertarget_enum()
        self.alienvault_enum()
        self.urlscan_enum()

        print("\n" + "=" * 55)
        print(f"[*] Total unique subdomains: {len(self.all_found)}")
        print("=" * 55)

        self.verify_dns()
        self.check_200()
        self.save_results()

# ---------------- MAIN ---------------- #

def main():
    parser = argparse.ArgumentParser(
        description="subs.py – Free Passive Subdomain Enumeration + HTTP 200"
    )
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()

    domain = re.sub(r"^https?://", "", args.domain).split("/")[0].lower()

    try:
        SubSpy(domain, output=args.output).run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(0)

if __name__ == "__main__":
    main()
