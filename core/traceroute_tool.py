import scapy.all as scapy
import argparse
import socket
import time

def traceroute(target_ip):
    
    print(f"[*] Tracing route to {target_ip}...")
    
  
    MAX_HOPS = 30
    TIMEOUT = 0.5
    
    
    udp_segment = scapy.UDP(dport=33434)
    
    for ttl_value in range(1, MAX_HOPS + 1):
        
        ip_packet = scapy.IP(dst=target_ip, ttl=ttl_value)
        
        
        packet = ip_packet / udp_segment
        
        
        start_time = time.time()
        reply = scapy.sr1(packet, timeout=TIMEOUT, verbose=False)
        end_time = time.time()
        
        latency_ms = round((end_time - start_time) * 1000, 2)
        
        
        if reply is None:
            
            print(f"{ttl_value:<3} * (Request timed out)")
        elif reply.haslayer(scapy.ICMP) and reply.getlayer(scapy.ICMP).type == 11:
           
            print(f"{ttl_value:<3} {reply.src:<16} {latency_ms} ms")
        elif reply.haslayer(scapy.ICMP) and reply.getlayer(scapy.ICMP).type == 3:
            
            print(f"{ttl_value:<3} {reply.src:<16} {latency_ms} ms (Destination Unreachable)")
            break 
        elif reply.haslayer(scapy.IP):
            
            print(f"{ttl_value:<3} {reply.src:<16} {latency_ms} ms (Target Reached!)")
            break
           
        if reply and reply.src == target_ip:
            break
            

def main():
    parser = argparse.ArgumentParser(description="Scapy-based Traceroute Tool")
    parser.add_argument("-t", "--target", dest="target_ip", required=True, help="Target IP address or hostname.")
    options = parser.parse_args()
    
    try:
       
        target_ip = socket.gethostbyname(options.target_ip)
    except socket.gaierror:
        print(f"[-] Error: Cannot resolve hostname '{options.target_ip}'. Exiting.")
        return
        
    traceroute(target_ip)

if __name__ == "__main__":
    main()