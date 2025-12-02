import requests
import argparse
from urllib.parse import urlparse

def web_server_fingerprint(url: str):
    
    if not urlparse(url).scheme:
        
        print(f"[*] Assuming HTTPS/HTTP. Testing {url}...")
        
        server_info = get_server_info(f"https://{url}")
        if server_info is None:
            
            server_info = get_server_info(f"http://{url}")
    else:
        server_info = get_server_info(url)
        
    print("\n" + "="*70)
    if server_info:
        print(f"Web Server Fingerprint for: **{server_info['Target URL']}**")
        print("-" * 70)
        print(f"{'Status Code':<15}: {server_info['Status Code']}")
        print(f"{'Server Header':<15}: {server_info['Server']}")
        print(f"{'X-Powered-By':<15}: {server_info['X-Powered-By']}")
        print(f"{'Content-Type':<15}: {server_info['Content-Type']}")
        print(f"{'Cookies Found':<15}: {server_info['Cookies Found']}")
    else:
        print(f"Error: Could not retrieve server information for {url}.")
        
    print("="*70)


def get_server_info(full_url: str):
    """Tries to connect and extract server headers."""
    try:
        
        headers = {'User-Agent': 'Mozilla/5.0 (ReconTool/1.0)'}
        response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=True)
        
        
        server = response.headers.get('Server', 'Not disclosed/Unknown')
        x_powered_by = response.headers.get('X-Powered-By', 'Not disclosed/None')
        content_type = response.headers.get('Content-Type', 'Unknown')
        
        return {
            "Target URL": full_url,
            "Status Code": response.status_code,
            "Server": server,
            "X-Powered-By": x_powered_by,
            "Content-Type": content_type,
            "Cookies Found": len(response.cookies) > 0,
        }
    except requests.exceptions.RequestException as e:
        
        print(f"[!] Failed to connect to {full_url}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Web Server Fingerprinting Tool (Header Analysis)")
    parser.add_argument("-u", "--url", dest="target_url", required=True, help="Target URL or domain (e.g., example.com or https://example.com).")
    options = parser.parse_args()
    
    web_server_fingerprint(options.target_url)

if __name__ == "__main__":
    main()