
import os
import subprocess
import time
from colorama import Fore, Style, init


init(autoreset=True)

CORE_PATH = "core/"   

def clear():
    os.system("cls" if os.name == "nt" else "clear")

LEGAL_NOTICE = f"""
{Fore.RED}{Style.BRIGHT}============================================================
   ⚠️ LEGAL NOTICE — EDUCATIONAL USE ONLY
------------------------------------------------------------
This toolkit must only be used on systems you OWN or have
WRITTEN permission to test. Unauthorized scanning is ILLEGAL.
============================================================
{Style.RESET_ALL}
"""


def run_script(script_name, args=""):
    clear()
    print(f"{Fore.YELLOW}[*] Running: {script_name} {args}\n")
    try:
        cmd = f"python3 {CORE_PATH}{script_name} {args}"
        subprocess.run(cmd, shell=True)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopped by user.")

    input(f"\n{Fore.CYAN}Press ENTER to return to menu...")


def main_menu():
    clear()
    print(Fore.CYAN + """
============================================================
           RECONX [CYBER FINGERPRINTING TOOLKIT]
============================================================
""")

    print(Fore.GREEN + "  1) Network Fingerprinting / Discovery")
    print(Fore.YELLOW + "  2) Reconnaissance Tools (DNS / WHOIS / Subdomains)")
    print(Fore.MAGENTA + "  3) Web Fingerprinting (Headers / SSL)")
    print(Fore.RED + "  0) Exit\n")

    return input(Fore.WHITE + "Enter your choice: ").strip()


def network_menu():
    clear()
    print(LEGAL_NOTICE)

    print(Fore.BLUE + """
================== NETWORK FINGERPRINTING ==================
""")

    print(Fore.GREEN + "  1) Live Host Discovery (ARP Scan)")
    print("  2) OS Fingerprinting (TTL)")
    print("  3) TCP Port Scanner")
    print("  4) Traceroute")
    print(Fore.RED + "  0) Back to Main Menu\n")

    return input(Fore.WHITE + "Select a tool: ").strip()


def recon_menu():
    clear()
    print(LEGAL_NOTICE)

    print(Fore.YELLOW + """
=================== RECONNAISSANCE ===================
""")

    print("  1) DNS Recon")
    print("  2) Reverse DNS Lookup")
    print("  3) WHOIS Lookup")
    print("  4) Subdomain Enumeration")
    print(Fore.RED + "  0) Back to Main Menu\n")

    return input(Fore.WHITE + "Select a tool: ").strip()


def web_menu():
    clear()
    print(LEGAL_NOTICE)

    print(Fore.MAGENTA + """
=================== WEB FINGERPRINTING ==================
""")

    print("  1) Web Server Fingerprint (Headers)")
    print("  2) SSL Certificate Inspector")
    print(Fore.RED + "  0) Back to Main Menu\n")

    return input(Fore.WHITE + "Select a tool: ").strip()


def start():
    while True:
        choice = main_menu()

        # NETWORK SECTION
        if choice == "1":
            while True:
                opt = network_menu()

                if opt == "1":
                    target = input("Enter IP range: ")
                    run_script("live_host_discovery.py", f"-t {target}")

                elif opt == "2":
                    target = input("Enter target IP: ")
                    run_script("os_fingerprint.py", f"-t {target}")

                elif opt == "3":
                    target = input("Enter host/IP: ")
                    ports = input("Enter ports (e.g. 1-1024): ")
                    run_script("scanner.py", f"-t {target} -p {ports}")

                elif opt == "4":
                    target = input("Enter IP/hostname: ")
                    run_script("traceroute_tool.py", f"-t {target}")

                elif opt == "0":
                    break

        # RECON SECTION
        elif choice == "2":
            while True:
                opt = recon_menu()

                if opt == "1":
                    domain = input("Enter domain: ")
                    run_script("dns_recon.py", f"-d {domain}")

                elif opt == "2":
                    target = input("Enter hostname/IP: ")
                    run_script("reverse_dns.py", f"-t {target}")

                elif opt == "3":
                    domain = input("Enter domain: ")
                    run_script("domain_lookup.py", f"-d {domain}")

                elif opt == "4":
                    domain = input("Enter domain: ")
                    run_script("subdomain_enum.py", f"-d {domain}")

                elif opt == "0":
                    break

        # WEB SECTION
        elif choice == "3":
            while True:
                opt = web_menu()

                if opt == "1":
                    url = input("Enter URL/domain: ")
                    run_script("web_fingerprint.py", f"-u {url}")

                elif opt == "2":
                    host = input("Enter hostname: ")
                    port = input("Enter port (default 443): ") or "443"
                    run_script("ssl_inspector.py", f"-t {host} -p {port}")

                elif opt == "0":
                    break

        elif choice == "0":
            clear()
            print(Fore.GREEN + "Exiting toolkit... Stay ethical. 👋")
            time.sleep(1)
            break

        else:
            input(Fore.RED + "Invalid option. Press ENTER to retry...")


if __name__ == "__main__":
    start()
