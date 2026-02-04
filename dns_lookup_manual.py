# manual/dns_lookup_manual.py
import socket
import struct
import random
import time

def build_dns_query(domain):
    # Random transaction ID
    transaction_id = random.randint(0, 65535)
    # Flags: 0x0100 = standard query, recursion desired
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Build QNAME
    qname = b""
    for part in domain.split('.'):
        qname += struct.pack("B", len(part)) + part.encode()
    qname += b'\x00'  # end

    # QTYPE=1 (A), QCLASS=1 (IN)
    question = qname + struct.pack(">HH", 1, 1)
    return header + question, transaction_id

def parse_dns_response(data):
    # Header is 12 bytes
    if len(data) < 12:
        return []
    header = data[:12]
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", header)

    # Skip question section
    offset = 12
    for _ in range(qdcount):
        # skip QNAME
        while True:
            length = data[offset]
            offset += 1
            if length == 0:
                break
            offset += length
        offset += 4  # QTYPE (2) + QCLASS (2)

    answers = []
    # Parse answer section
    for _ in range(ancount):
        # Name: usually pointer (2 bytes)
        # we skip 2 bytes (name pointer)
        offset += 2
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10
        if rtype == 1 and rdlength == 4:  # A record (IPv4)
            ip_parts = struct.unpack(">BBBB", data[offset:offset+4])
            ip_addr = "{}.{}.{}.{}".format(*ip_parts)
            answers.append({"type": "A", "value": ip_addr, "ttl": ttl})
            
        elif rtype == 28 and rdlength == 16:  # AAAA record (IPv6)
            ipv6_parts = struct.unpack(">8H", data[offset:offset+16])
            ipv6_addr = ":".join(format(part, "x") for part in ipv6_parts)
            answers.append({"type": "AAAA", "value": ipv6_addr, "ttl": ttl})

        elif rtype == 5:  # CNAME record
            cname = ""
            ptr = offset
            while data[ptr] != 0:
                length = data[ptr]
                ptr += 1
                cname += data[ptr:ptr+length].decode() + "."
                ptr += length
            answers.append({"type": "CNAME", "value": cname, "ttl": ttl})

        offset += rdlength
    return answers

def dns_lookup(domain, dns_server="8.8.8.8", timeout=5):
    query, txid = build_dns_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    result_str = ""  # This will store all output as a string
    
    try:
        start = time.time()  # Start timer
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(4096)
        end = time.time()    # End timer
        
        response_time = (end - start) * 1000  # milliseconds
        result_str += f"Lookup completed in {response_time:.2f} ms\n\n"
        
        ips = parse_dns_response(data)
        if ips:
            result_str += f"Domain: {domain}\nResolved IP addresses via {dns_server}:\n"
            for record in ips:
                # record can be dict with type, value, ttl
                if isinstance(record, dict):
                    result_str += f" - {record.get('type','A')} → {record.get('value')} (TTL: {record.get('ttl','N/A')}s)\n"
                else:
                    result_str += f" - {record}\n"
            
            # Logging
            try:
                log_entry = f"Domain: {domain}, Server: {dns_server}, Result: {ips}, Time: {response_time:.2f} ms\n"
                with open("logs/dns_results.log", "a") as log_file:
                    log_file.write(log_entry)
                result_str += "\n✅ Lookup result saved to logs/dns_results.log\n"
            except Exception as e:
                result_str += f"\n⚠️ Could not save log: {e}\n"
        else:
            result_str += "No A records found in response or failed to parse response.\n"
    
    except socket.timeout:
        result_str += f"Timed out waiting for a reply from {dns_server}\n"
    except Exception as e:
        result_str += f"Error: {e}\n"
    finally:
        sock.close()
    
    return result_str


if __name__ == "__main__":
    domain = input("Enter domain name (e.g., google.com): ").strip()
    dns_servers = ["8.8.8.8", "1.1.1.1"]  # Google, Cloudflare
    for server in dns_servers:
        print("\nQuerying DNS server:", server)
        dns_lookup(domain, dns_server=server)
