import requests
import argparse
import re

def get_subdomains(domain):
    print(f"[*] Fetching subdomains for: {domain} ...")

    url = f"https://crt.sh/?q={domain}&output=json"

    try:
        response = requests.get(url, timeout=10)
        data = response.json()
    except Exception as e:
        print(f"[!] Error fetching data: {e}")
        return []

    subdomains = set()

    for entry in data:
        name = entry.get("name_value", "")
        
        for sub in name.split("\n"):
            
            sub = sub.strip()
            sub = sub.replace("*.", "")
            if sub.endswith(domain):
                subdomains.add(sub)

    return sorted(subdomains)


def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Without Wordlist")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    args = parser.parse_args()

    subs = get_subdomains(args.domain)

    print("\n========== Subdomains Found ==========")
    for s in subs:
        print(f"[+] {s}")

    print("======================================")
    print(f"[✓] Total subdomains found: {len(subs)}")


if __name__ == "__main__":
    main()
