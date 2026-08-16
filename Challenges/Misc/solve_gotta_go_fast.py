import hashlib
import json
import time

from Crypto.Util.number import long_to_bytes
from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13372


def key_for(timestamp):
    return hashlib.sha256(long_to_bytes(timestamp)).digest()


r = remote(HOST, PORT)
print(r.recvline().decode())

t_before = int(time.time())
r.sendline(json.dumps({"option": "get_flag"}).encode())
resp = json.loads(r.recvline())
t_after = int(time.time())
print(resp)

ct = bytes.fromhex(resp["encrypted_flag"])

flag = None
for t in range(t_before - 2, t_after + 3):
    key = key_for(t)
    pt = bytes(c ^ k for c, k in zip(ct, key))
    if pt.startswith(b"crypto{"):
        flag = pt
        break

print(flag.decode())
