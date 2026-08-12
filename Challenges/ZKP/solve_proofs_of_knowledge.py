import json
import random

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13425

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Same w the challenge source hands the prover -- it is the witness for
# g^w = y mod p, i.e. exactly what an honest prover is assumed to know.
w = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83

r = remote(HOST, PORT)
print(r.recvline().decode())

# Schnorr proof of knowledge, run honestly:
#   commitment: a = g^r mod p
r_val = random.randint(0, q - 1)
a = pow(g, r_val, p)
r.sendline(json.dumps({"a": a}).encode())

resp = json.loads(r.recvline())
print(resp)
e = resp["e"]

#   response: z = r + e*w mod q
z = (r_val + e * w) % q
r.sendline(json.dumps({"z": z}).encode())

resp = json.loads(r.recvline())
print(resp)
