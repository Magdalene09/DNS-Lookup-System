# basic/dns_lookup_basic.py
import socket

def dns_lookup(domain_name):
    try:
        ip_address = socket.gethostbyname(domain_name)
        print(f"Domain Name: {domain_name}")
        print(f"Resolved IP Address: {ip_address}")
    except socket.gaierror as e:
        print("Unable to resolve domain. Please check the name and try again.")
        print("Error:", e)

if __name__ == "__main__":
    domain = input("Enter domain name (e.g., google.com): ").strip()
    if domain:
        dns_lookup(domain)
    else:
        print("No domain entered.")
