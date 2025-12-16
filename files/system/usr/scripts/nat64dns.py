import socket
import struct
import ipaddress
from dnslib import DNSRecord, DNSHeader, RR, AAAA, QTYPE, RCODE

# Configuration
LISTEN_ADDR = "::53"
LISTEN_PORT = 53
NAT64_SUFFIX = "nat64"
BASE_PREFIX = "64:ff9b:0001::"


class NAT64Resolver:
    def resolve(self, qname_str):
        """
        Parses the query name and returns an ipaddress.IPv6Address or None.
        Format expected:
          1. 10-11-0-5.aa.nat64 (Site ID defaults to 0)
          2. 10-11-0-5.tfaa.nat64 (Leading 't' stripped)
          3. 10-11-0-1.a.faa.nat64 (Explicit Site ID 'a')
        """

        # Ensure it ends with our TLD
        clean_qname = qname_str.lower().rstrip(".")
        if not clean_qname.endswith(NAT64_SUFFIX):
            return None

        # Remove the TLD part
        # content becomes: "10-11-0-5.aa" or "10-11-0-1.a.faa"
        prefix_len = len(NAT64_SUFFIX) + 1 # +1 for dot
        content = clean_qname[:-prefix_len]
        parts = content.split(".")

        # We expect at least 2 parts (IPv4 part and CustomerID)
        # and at most 3 parts (IPv4 part, SiteID, CustomerID)
        if len(parts) < 2 or len(parts) > 3:
            return None

        ipv4_part_str = parts[0]
        customer_id_str = parts[-1]  # Always the last part before nat64
        site_id_str = "0"            # Default

        # Handle explicit Site ID if 3 parts exist
        if len(parts) == 3:
            site_id_str = parts[1]

        # --- Parse Customer ID ---
        # Strip optional leading 't'
        if customer_id_str.startswith("t"):
            customer_id_str = customer_id_str[1:]

        try:
            customer_id = int(customer_id_str, 16)
            if customer_id > 0xFFFFFF: # Max 24 bits
                return None
        except ValueError:
            return None

        # --- Parse Site ID ---
        try:
            site_id = int(site_id_str, 16)
            if site_id > 0xFF: # Max 8 bits
                return None
        except ValueError:
            return None

        # --- Parse IPv4 Address ---
        try:
            # Convert 10-11-0-5 -> 10.11.0.5
            dotted_ipv4 = ipv4_part_str.replace("-", ".")
            ipv4_obj = ipaddress.IPv4Address(dotted_ipv4)
            ipv4_int = int(ipv4_obj)
        except (ValueError, ipaddress.AddressValueError):
            return None

        # --- Construct IPv6 Address ---

        # Base Prefix Integer
        base_net = ipaddress.IPv6Network(BASE_PREFIX + "/96")
        base_int = int(base_net.network_address)

        # Shift logic:

        # Customer ID is "up to 24 bits".
        # Site ID is "8 bits".
        # IPv4 is "32 bits".
        # 24 + 8 + 32 = 64 bits.

        # So we take the upper 64 bits of the base address, and add our 64 bits constructed data.

        constructed_suffix = (customer_id << 40) | (site_id << 32) | ipv4_int
        final_int = base_int | constructed_suffix

        return ipaddress.IPv6Address(final_int)


def handle_request(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = request.q.qtype

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        resolver = NAT64Resolver()

        # We only care about AAAA records (QTYPE 28)
        if qtype == QTYPE.AAAA:
            result_ip = resolver.resolve(qname)

            if result_ip:
                reply.add_answer(
                    RR(
                        rname=qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=300,
                        rdata=AAAA(str(result_ip)),
                    )
                )
            else:
                reply.header.rcode = RCODE.NOERROR
        else:
             reply.header.rcode = RCODE.NOERROR

        sock.sendto(reply.pack(), addr)
        print(f"Query: {qname} [{QTYPE[qtype]}] -> {RCODE[reply.header.rcode]}")

    except Exception as e:
        print(f"Error handling request: {e}")


def main():
    # Create IPv6 UDP socket
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    try:
        sock.bind((LISTEN_ADDR, LISTEN_PORT))
        print(f"DNS Server listening on [{LISTEN_ADDR}]:{LISTEN_PORT}")

        while True:
            data, addr = sock.recvfrom(512)
            handle_request(data, addr, sock)

    except PermissionError:
        print(f"Permission denied. Try running with sudo/admin privileges to bind to port {LISTEN_PORT}.")
    except Exception as e:
        print(f"Fatal error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
