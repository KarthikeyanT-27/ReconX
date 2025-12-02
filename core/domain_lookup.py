import whois
import argparse
import socket
from typing import Dict, Any

def whois_lookup(domain_name: str) -> Dict[str, Any]:
   
    print(f"[*] Performing WHOIS lookup for: {domain_name}...")
    
    try:
        
        w = whois.whois(domain_name)
        
        data = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Last Updated": w.updated_date,
            "Nameservers": w.nameservers,
            "Organization": w.org,
            "Status": w.status,
            "Emails": w.emails,
        }
        
        return data

    except whois.parser.PywhoisError as e:
        
        return {"Error": f"Could not retrieve WHOIS data. Domain may not exist or error: {e}"}
    except Exception as e:
        return {"Error": f"An unexpected error occurred: {e}"}


def print_whois_result(results: Dict[str, Any]):
    """Prints the structured WHOIS results."""
    
    if "Error" in results:
        print(f"\n[!] {results['Error']}")
        return

    print("\n" + "="*60)
    print(f"WHOIS Lookup Results for: **{results.get('Domain Name', 'N/A')}**")
    print("="*60)
    
    
    for key, value in results.items():
        if key == "Domain Name":
            continue
            
        
        if isinstance(value, list):
            value = "\n    - " + "\n    - ".join(map(str, value))
        
        
        if isinstance(value, (list, tuple)) and all(isinstance(i, (str, type(None))) for i in value):
             
             value = value[0] if value else 'N/A'
        
        print(f"**{key:<18}**: {value}")
        
    print("="*60)


def main():
    parser = argparse.ArgumentParser(description="Python WHOIS Lookup Tool")
    parser.add_argument("-d", "--domain", dest="domain_name", required=True, help="Target domain name (e.g., example.com).")
    options = parser.parse_args()
    
    
    domain_input = options.domain_name.lower().replace('http://', '').replace('https://', '').split('/')[0]
    
    results = whois_lookup(domain_input)
    print_whois_result(results)


if __name__ == "__main__":
    main()