"""Client simulation against an already running `jitca serve` on default ports."""
import socket
import ssl
import struct
from pathlib import Path

HOST = "robot.example.test"
DNS_PORT = 15353
HTTPS_PORT = 18443
CA_FILE = Path(__file__).resolve().parent / "state" / "certificates" / "demo-root.crt"

labels = b"".join(bytes([len(p)]) + p.encode() for p in HOST.split(".")) + b"\x00"
query = struct.pack("!HHHHHH", 123, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
    dns.settimeout(3)
    dns.sendto(query, ("127.0.0.1", DNS_PORT))
    packet = dns.recvfrom(1500)[0]
    assert int.from_bytes(packet[6:8], "big") == 1
    print("DNS A:", socket.inet_ntoa(packet[-4:]))

context = ssl.create_default_context(cafile=str(CA_FILE))
with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5) as connection:
    with context.wrap_socket(connection, server_hostname=HOST) as tls:
        negotiated = tls.version()
        tls.sendall(b"GET /status HTTP/1.1\r\nHost: robot.example.test\r\nConnection: close\r\n\r\n")
        chunks = []
        while chunk := tls.recv(8192):
            chunks.append(chunk)
        print("TLS:", negotiated)
        print(b"".join(chunks).decode())
