#----- proxychains bloodhound-python -u alfred -p 'P@ssw0rd' -d gotham.local -dc dc09.gotham.local -ns 127.0.0.1 -c All --zip
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: gotham.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc09.gotham.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: dc09.gotham.local
INFO: Found 15 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer:
INFO: Querying computer: file05.gotham.local
INFO: Querying computer: starlabs.gotham.local
INFO: Querying computer: arkham.gotham.local
INFO: Querying computer: dc09.gotham.local
INFO: Skipping enumeration for starlabs.gotham.local since it could not be resolved.
INFO: Connecting to GC LDAP server: dc09.gotham.local
INFO: Done in 00M 11S
INFO: Compressing output into 20250629044946_bloodhound.zip

#----- output
└─$ sudo python dnssockfwd.py
[+] DNS forwarder listening on 127.0.0.1:53 (SOCKS → 172.16.10.100)
[+] Forwarded: _ldap._tcp.pdc._msdcs.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: _ldap._tcp.gc._msdcs.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: _kerberos._tcp.dc._msdcs.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: dc09.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: file05.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: arkham.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: starlabs.gotham.local. → 172.16.10.100 via SOCKS
[+] Forwarded: starlabs.gotham.local.lt-indonesia.com. → 172.16.10.100 via SOCKS

----
cat dnssockfwd.py
import socket
import threading
import socks
import struct
from dnslib import DNSRecord

# === CONFIG ===
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 53  # Must run as root if port < 1024

SOCKS_PROXY_IP = "127.0.0.1"
SOCKS_PROXY_PORT = 1080  # e.g., for proxychains or Tor

UPSTREAM_DNS_IP = "172.16.10.100"
UPSTREAM_DNS_PORT = 53  # Make sure this DNS server supports TCP

# === FUNCTION ===
def handle_client(data, addr, sock):
    try:
        # Prefix the DNS query with TCP length
        tcp_query = struct.pack(">H", len(data)) + data

        # SOCKS-wrapped TCP connection
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, SOCKS_PROXY_IP, SOCKS_PROXY_PORT)
        s.connect((UPSTREAM_DNS_IP, UPSTREAM_DNS_PORT))
        s.sendall(tcp_query)

        # Receive length-prefixed DNS TCP response
        length_prefix = s.recv(2)
        if len(length_prefix) < 2:
            print(f"[!] Incomplete length prefix from upstream")
            return

        response_len = struct.unpack(">H", length_prefix)[0]
        response_data = b""
        while len(response_data) < response_len:
            response_data += s.recv(response_len - len(response_data))
        s.close()

        # Send back to original client over UDP
        sock.sendto(response_data, addr)

        # Optional: decode DNS for logging
        try:
            qname = DNSRecord.parse(data).q.qname
            print(f"[+] Forwarded: {qname} → {UPSTREAM_DNS_IP} via SOCKS")
        except:
            pass

    except Exception as e:
        print(f"[!] SOCKS proxy error: {e}")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[+] DNS forwarder listening on {LISTEN_IP}:{LISTEN_PORT} (SOCKS → {UPSTREAM_DNS_IP})")

    while True:
        data, addr = sock.recvfrom(512)
        threading.Thread(target=handle_client, args=(data, addr, sock)).start()

if __name__ == "__main__":
    main()
