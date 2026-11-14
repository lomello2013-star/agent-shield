import socket
import struct


def query(qname: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(query("a" * 50 + ".example"), ("127.0.0.1", 53))
    s.sendto(query("a.example"), ("127.0.0.1", 53))
except OSError:
    pass
finally:
    s.close()
