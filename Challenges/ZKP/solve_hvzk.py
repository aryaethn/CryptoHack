import json
import random

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13427

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

r = remote(HOST, PORT)
print(r.recvline().decode())

resp = json.loads(r.recvline())
print(resp)
e = resp["e"]
y = resp["y"]

# HVZK simulator: pick z first, then back out a = g^z * y^-e mod p so the
# verification g^z == a*y^e mod p holds by construction -- no witness needed.
z = random.randint(0, q - 1)
a = (pow(g, z, p) * pow(y, -e, p)) % p

r.sendline(json.dumps({"a": a, "z": z}).encode())

resp = json.loads(r.recvline())
print(resp)
