import ssl
import socket
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.extensions import SubjectAlternativeName



def get_ssl_certificate(hostname: str, port: int = 443) -> Optional[Any]:
    """
    Connects to the specified host and port, retrieves the SSL certificate object.
    """
    print(f"[*] Fetching SSL certificate from {hostname}:{port}...")
    
    try:
        # 1. Establish a TCP connection
        sock = socket.create_connection((hostname, port), timeout=5)
        
        # 2. Wrap the socket with SSL/TLS context
        context = ssl.create_default_context()
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        
        # 3. Get the certificate in binary DER format
        cert_der = ssock.getpeercert(True)
        
        # 4. Use cryptography to parse the binary DER format
        x509_cert = load_der_x509_certificate(cert_der, default_backend())
        
        ssock.close()
        
        return x509_cert
        
    except socket.gaierror:
        print(f"[!] Error: Hostname '{hostname}' could not be resolved.")
    except ssl.SSLError as e:
        print(f"[!] SSL/TLS Handshake Error: {e}")
    except socket.error as e:
        print(f"[!] Connection Error: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        
    return None

def extract_cert_details(x509_cert) -> Dict[str, Any]:
    
    details: Dict[str, Any] = {}

    # --- 1. Issuer & Subject ---
    try:
        # Safely extract Issuer
        details["Issuer"] = x509_cert.issuer.rfc4514_string()
    except Exception:
        details["Issuer"] = "N/A (Error Reading Issuer)"
    
    try:
       
        subject_cn = x509_cert.subject.get_attributes_for_oid(x509_cert.subject.common_name)[0].value
        details["Common Name (CN)"] = subject_cn
    except (IndexError, AttributeError): 
        details["Common Name (CN)"] = "N/A (Missing CN)"

    # --- 2. Validity ---
    details["Valid From"] = x509_cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    details["Valid To"] = x509_cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    current_time_utc = datetime.now(timezone.utc)
    details["Valid Days Left"] = (x509_cert.not_valid_after_utc - current_time_utc).days

    # --- 3. SAN (Subject Alternative Names) ---
    san_list: List[str] = []
    try:
        ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_ext: SubjectAlternativeName = ext.value
        san_list = [name.value for name in san_ext.get_values_for_type(san_ext.get_names()) if isinstance(name.value, str)]
    except Exception:
        pass # Extension is not present or cannot be parsed
    details["Subject Alt Names (SAN)"] = san_list if san_list else "N/A"

    # --- 4. Signature Algorithm ---
    details["Signature Algorithm"] = x509_cert.signature_hash_algorithm.name.upper()

    # --- 5. Key Type & Size ---
    key = x509_cert.public_key()
    details["Key Type"] = key.__class__.__name__.replace("PublicKey", "")
    try:
        details["Key Size"] = getattr(key, 'key_size', key.curve.name)
    except AttributeError:
        details["Key Size"] = "Unknown"
        
    return details


def print_cert_details(details: Dict[str, Any]):
    """Prints the extracted certificate details in a formatted table."""
    
    print("\n" + "=" * 80)
    print("✨ **TLS/SSL Certificate Fingerprint**")
    print("-" * 80)
    
    # 1. Identity and Signature
    print("### 🆔 Identity & Authority")
    print(f"{'Issuer':<25}: {details['Issuer']}")
    print(f"{'Common Name (CN)':<25}: {details['Common Name (CN)']}")
    print(f"{'Signature Algorithm':<25}: {details['Signature Algorithm']}")
    
    # 2. Key Details
    print("\n### 🔑 Key Details")
    print(f"{'Key Type':<25}: {details['Key Type']}")
    print(f"{'Key Size/Curve':<25}: {details['Key Size']}")
    
    # 3. Validity and Expiry
    print("\n### 📅 Validity Period")
    print(f"{'Valid From':<25}: {details['Valid From']}")
    print(f"{'Valid To':<25}: {details['Valid To']}")
    print(f"{'Days Remaining':<25}: {details['Valid Days Left']}")
    
    # 4. Subject Alternative Names (SAN)
    print("\n### 🌐 Subject Alternative Names (SAN)")
    san_list = details['Subject Alt Names (SAN)']
    if san_list == "N/A":
        print(f"{'SAN Domains':<25}: N/A")
    else:
        print(f"{'Primary Domain':<25}: {san_list[0]}")
        for i, domain in enumerate(san_list[1:], 1):
            print(f"{f'Domain {i+1}':<25}: {domain}")
    
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="TLS/SSL Certificate Inspector Tool")
    parser.add_argument("-t", "--target", dest="target_host", required=True, help="Target hostname (e.g., example.com).")
    parser.add_argument("-p", "--port", dest="target_port", type=int, default=443, help="Target port (default is 443).")
    
    options = parser.parse_args()
    
    try:
        import cryptography
    except ImportError:
        print("\n[!!!] FATAL ERROR: The 'cryptography' library is required for advanced key and SAN extraction.")
        print("Please install it: pip install cryptography")
        return

    x509_cert = get_ssl_certificate(options.target_host, options.target_port)
    
    if x509_cert:
        details = extract_cert_details(x509_cert)
        
       
        if details.get("Issuer", None) is not None:
            print_cert_details(details)
        else:
             print("[!] Could not extract certificate details, likely due to a parsing error. Check connection and logs.")


if __name__ == "__main__":
    main()