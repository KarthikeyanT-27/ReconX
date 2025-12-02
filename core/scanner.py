import socket
import threading
import time
import concurrent.futures
import argparse
from typing import List, Dict, Any

TIMEOUT = 0.5
MAX_WORKERS = 100
BANNER_READ = 1024


def grab_banner(s: socket.socket, port: int) -> str:
    """
    Grab banner/version from open port.
    Works for FTP, SSH, SMTP, POP3, IMAP, HTTP, etc.
    """
    try:
        s.settimeout(0.5)

        
        if port in [80, 8080, 8000]:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = s.recv(BANNER_READ)
        if banner:
            return banner.decode("utf-8", errors="ignore").strip()[:120]
        return "No Banner"

    except:
        return "No Banner"


def tcp_connect_scan(target_ip: str, port: int) -> Dict[str, Any]:
    result = {"port": port, "status": "closed", "service": None, "banner": None}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        
        if s.connect_ex((target_ip, port)) == 0:
            result["status"] = "open"

            # ---- SERVICE NAME DETECTION ----
            try:
                result["service"] = socket.getservbyport(port, "tcp")
            except:
                result["service"] = "unknown"

            # ---- BANNER / VERSION DETECTION ----
            banner = grab_banner(s, port)
            result["banner"] = banner

        s.close()

    except Exception as e:
        result["status"] = "Error"
        result["service"] = f"Socket Error: {e}"

    return result


def get_ports_to_scan(port_range: str) -> List[int]:
    ports = []
    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return [p for p in ports if 1 <= p <= 65535]


def run_multithreaded_scan(target_ip: str, ports: List[int]):
    print(f"[*] Starting TCP Scan on {target_ip}...\n")

    open_ports = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_port = {executor.submit(tcp_connect_scan, target_ip, port): port for port in ports}

        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result["status"] == "open":
                open_ports.append(result)

    print("="*100)
    print(f"{'Port':<8} {'Service':<12} {'Banner / Version'}")
    print("-"*100)

    if open_ports:
        for entry in sorted(open_ports, key=lambda x: x['port']):
            print(f"{entry['port']:<8} {entry['service']:<12} {entry['banner']}")
    else:
        print("No open ports found.")

    print("="*100)
    print(f"Scan finished in {time.time() - start_time:.2f} seconds.")


def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner with Service + Banner Detection")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-1024")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Hostname resolution failed.")
        return

    ports = get_ports_to_scan(args.ports)
    run_multithreaded_scan(target_ip, ports)


if __name__ == "__main__":
    main()
