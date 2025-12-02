import scapy.all as scapy
import argparse
import socket

def get_os_from_ttl(ttl):
   
    if ttl <= 64:
        
        return "Linux/Unix/macOS (Initial TTL likely 64)"
    elif ttl <= 128:
       
        return "Windows (Initial TTL likely 128)"
    elif ttl <= 255:
        
        return "Older Unix/Cisco Device (Initial TTL likely 255)"
    else:
        return "Unknown"

def os_fingerprint(target_ip):
   
    print(f"[*] Attempting TTL-based OS fingerprinting for {target_ip}...")
    
    # 1. Craft an ICMP Echo Request packet
    icmp_request = scapy.ICMP()
    ip_packet = scapy.IP(dst=target_ip)
    packet = ip_packet / icmp_request
    
    # 2. Send the packet and wait for a reply
    reply = scapy.sr1(packet, timeout=1, verbose=False)
    
    if reply is None:
        print("[!] No response received. Target is down or blocked ICMP.")
        return
        
    # 3. Analyze the received TTL
    if reply.haslayer(scapy.IP):
        received_ttl = reply.getlayer(scapy.IP).ttl
        inferred_os = get_os_from_ttl(received_ttl)
        
        print("-" * 50)
        print(f"Target IP: {reply.src}")
        print(f"Received TTL: {received_ttl}")
        print(f"Inferred OS: {inferred_os}")
        print("-" * 50)
    else:
        print("[!] Received a non-IP response. Cannot fingerprint.")

def main():
    parser = argparse.ArgumentParser(description="TTL-based OS Fingerprinting Tool")
    parser.add_argument("-t", "--target", dest="target_ip", required=True, help="Target IP address or hostname.")
    options = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(options.target_ip)
    except socket.gaierror:
        print(f"[-] Error: Cannot resolve hostname '{options.target_ip}'. Exiting.")
        return
        
    os_fingerprint(target_ip)

if __name__ == "__main__":
    main()