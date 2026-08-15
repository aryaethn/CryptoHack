import json
import random
from hashlib import sha512

from pwn import remote
from Crypto.Util.number import bytes_to_long

HOST = "socket.cryptohack.org"
PORT = 13428

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Same witness the challenge source hands the prover.
w = 0xdb968f9220c879b58b71c0b70d54ef73d31b1627868921dfc25f68b0b9495628b5a0ea35a80d6fd4f2f0e452116e125dc5e44508b1aaec89891dddf9a677ddc0

r = remote(HOST, PORT)
print(r.recvline().decode())

resp = json.loads(r.recvline())
print(resp)

# Fiat-Shamir: build the whole (a, e, z) transcript ourselves, deriving the
# "verifier" challenge e as a hash of the commitment a instead of waiting for
# an interactive challenge.
r_val = random.randint(0, q - 1)
a = pow(g, r_val, p)
e = bytes_to_long(sha512(str(a).encode()).digest()) % 2**511
z = (r_val + e * w) % q

r.sendline(json.dumps({"a": a, "z": z}).encode())

resp = json.loads(r.recvline())
print(resp)
