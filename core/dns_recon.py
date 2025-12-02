import dns.resolver
import argparse
import socket
from typing import List, Dict, Any, Optional

# --- DNS Record Types to Query ---

RECORDS_TO_QUERY = [
    'A',      
    'AAAA',   
    'NS',     
    'MX',     
    'TXT',    
    'PTR',   
    'SOA',    
    'CNAME',  
]

def dns_query(domain: str, record_type: str) -> List[str]:
    
    results = []
    try:
        
        answers = dns.resolver.resolve(domain, record_type, lifetime=2.0) 
        
        for rdata in answers:
            
            if record_type in ['A', 'AAAA', 'NS', 'MX', 'PTR', 'CNAME']:
                
                if record_type == 'MX':
                    results.append(f"{rdata.preference} {rdata.exchange}")
                else:
                    results.append(str(rdata))
            elif record_type == 'TXT':
                
                txt_data = b"".join(rdata.strings).decode('utf-8', errors='ignore')
                results.append(txt_data)
            else:
                results.append(str(rdata).split('\n')[0]) 
                
    except dns.resolver.NoAnswer:
        pass  
    except dns.resolver.NXDOMAIN:
        
        results.append(f"[!] Domain {domain} does not exist.")
    except dns.exception.Timeout:
        results.append("[!] Query timed out.")
    except Exception as e:
        results.append(f"[!] Error querying {record_type}: {e}")
        
    return results


def dns_recon(domain_name: str):
    
    print(f"[*] Starting DNS Reconnaissance for: {domain_name}\n")
    
    all_results = {}
    
    
    if domain_name.startswith('http') or '/' in domain_name:
        print("[!] Input must be a bare domain name (e.g., example.com).")
        return

    print("="*80)
    print(f"{'Record Type':<15} | {'Query Target':<30} | Result(s)")
    print("-" * 80)

    for record in RECORDS_TO_QUERY:
        
        if record == 'PTR':
            continue 

        target = domain_name
        results = dns_query(target, record)
        all_results[record] = results
        
        if results:
            print(f"{record:<15} | {target:<30} | {results[0]}")
            
            for res in results[1:]:
                print(f"{'':<15} | {'':<30} | {res}")
            print("-" * 80)
        else:
            print(f"{record:<15} | {target:<30} | N/A")
            print("-" * 80)

    print("\n[i] Scan Complete. The A and AAAA records are the IP addresses for the web server.")
    print("[i] NS records are useful for targeted zone transfer attempts (next step).\n")


def main():
    parser = argparse.ArgumentParser(description="DNS Enumeration Tool (A, AAAA, MX, NS, TXT, etc.)")
    parser.add_argument("-d", "--domain", dest="domain_name", required=True, help="Target domain name (e.g., example.com).")
    options = parser.parse_args()
    
    dns_recon(options.domain_name)

if __name__ == "__main__":
    main()