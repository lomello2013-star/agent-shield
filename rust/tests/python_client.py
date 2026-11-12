import sys
from multiprocessing.connection import Client

address = sys.argv[1]
if address.startswith("\\\\.\\pipe\\"):
    target = address
elif address.isdigit():
    target = ("127.0.0.1", int(address))
else:
    target = address
conn = Client(target, authkey=b"secret")
conn.send({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"token": "tok"}})
print(conn.recv(), flush=True)
conn.send({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
print(conn.recv(), flush=True)
conn.close()
