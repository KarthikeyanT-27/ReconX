import socket
import argparse
import dns.resolver
from typing import Optional, Dict, Any

# --- 1. Forward DNS Lookup (Hostname to IP) ---

def forward_lookup(hostname: str) -> Optional[str]:
    
    try:
        
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None
    except Exception as e:
        return f"Error: {e}"


# --- 2. Reverse DNS Lookup (IP to Hostname) ---

def reverse_lookup(ip_address: str) -> Optional[str]:
    """
    Performs a formal Reverse DNS query using dnspython for the PTR record.
    """
    try:
        
        reverse_name = dns.reversename.from_address(ip_address)
        
        
        answers = dns.resolver.resolve(reverse_name, "PTR", lifetime=2.0)
        
        
        if answers:
            
            return str(answers[0]).rstrip('.')
        
    except dns.resolver.NXDOMAIN:
       
        return None
    except dns.exception.Timeout:
        return "[!] Query timed out."
    except Exception as e:
        
        return f"Error: {e}"


# --- 3. Main Execution and Formatting ---

def main():
    parser = argparse.ArgumentParser(description="Forward (DNS to IP) and Reverse (IP to DNS) Lookup Tool")
    
    
    parser.add_argument("-t", "--target", dest="target_input", required=True, 
                        help="Target hostname (e.g., google.com) or IP address (e.g., 142.250.76.206).")
    options = parser.parse_args()
    target = options.target_input

    print("\n" + "=" * 60)
    print(f"Lookup Tool for Target: **{target}**")
    print("-" * 60)
    
    
    try:
        
        ip_result = forward_lookup(target)
        if ip_result and not ip_result.startswith("Error"):
            print("Mode: **Forward DNS Lookup**")
            print(f"Hostname: {target}")
            print(f"Resolved IP: {ip_result}")
            
            print("-" * 60)
            print("Attempting Reverse Lookup on Resolved IP...")
            
            hostname_result = reverse_lookup(ip_result)
            if hostname_result and not hostname_result.startswith("Error"):
                print(f"IP-to-Hostname: {hostname_result}")
            else:
                print("Reverse Lookup: No PTR record found or timed out.")
            
            print("-" * 60)
            return

    except Exception:
        pass 

    
    print("Mode: **Reverse DNS Lookup**")
    hostname_result = reverse_lookup(target)
    
    if hostname_result and not hostname_result.startswith("Error"):
        print(f"Input IP: {target}")
        print(f"Resolved Hostname (PTR): {hostname_result}")
    else:
        print(f"Input IP: {target}")
        print("Resolved Hostname (PTR): No PTR record found.")

    print("=" * 60)


if __name__ == "__main__":
    main()