import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"A" * 12_000_000, ("127.0.0.1", 9))
except OSError:
    pass
finally:
    s.close()
