import scapy.all as scapy
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import argparse

# --- 1. MAC Vendor Lookup Setup (Revised) ---


try:
    mac_lookup = MacLookup()
    
except Exception as e:
    print(f"Error initializing MAC Lookup: {e}")
    print("Vendor lookup might be unavailable. Check installation or internet connection.")
    mac_lookup = None


def get_vendor_info(mac_address):
    """
    Looks up the vendor name for a given MAC address, normalizing the format first.
    """
    if not mac_lookup:
        return "N/A (Lookup Failed)"
    
    normalized_mac = mac_address.upper()
    
  
    try:
        oui = normalized_mac[:8].replace(':', '-').upper()
    except IndexError:
        oui = "Invalid MAC Format"
        return f"Unknown Vendor (OUI: {oui})"
    
    try:
        
        vendor = mac_lookup.lookup(normalized_mac)
        return vendor
    except VendorNotFoundError:
        
        return f"Unknown Vendor (OUI: {oui})" 
    except Exception as e:
        return f"Lookup Error: {e}"

# --- 2. Network Scanning Function (ARP Scan) ---

def scan_network(ip_range):
    """Performs an ARP scan on the local network for the given IP range."""
    print(f"[*] Scanning network range: {ip_range} (Requires root/admin privileges)...")
    
   
    arp_request = scapy.ARP(pdst=ip_range)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    broadcast_packet = ether_frame / arp_request
    
    
    answered_list = scapy.srp(broadcast_packet, timeout=1, verbose=False)[0]
    
    hosts_list = []
    
   
    for sent, received in answered_list:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_vendor_info(mac)
        
        hosts_list.append({"ip": ip, "mac": mac, "vendor": vendor})

    return hosts_list

# --- 3. Output Formatting ---

def print_result(hosts_list):
    """Prints the scan results in a formatted table."""
    
    if not hosts_list:
        print("\n[!] No active hosts found or scan failed.")
        return

    print("\n" + "="*70)
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Vendor/Owner'}")
    print("-" * 70)
    
    for client in hosts_list:
        print(f"{client['ip']:<18} {client['mac']:<20} {client['vendor']}")
    
    print("="*70)


# --- 4. Main Execution and Argument Parsing ---

def get_arguments():
    """Sets up and parses command-line arguments."""
    parser = argparse.ArgumentParser(description="ARP Network Scanner with MAC Vendor Lookup")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP range (e.g., 192.168.1.1/24)")
    
    options = parser.parse_args()
    
    if not options.target_ip:
        parser.error("[-] Please specify a target IP range. Use --help for details.")
    
    return options

if __name__ == "__main__":
    
    options = get_arguments() 
    
    scanned_hosts = scan_network(options.target_ip)
    
    print_result(scanned_hosts)