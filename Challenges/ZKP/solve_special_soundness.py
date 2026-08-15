import json

from pwn import remote
from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13426

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

r = remote(HOST, PORT)
print(r.recvline().decode())

# Round 1: prover sends a = g^r mod p, we pick e1 and get back z = r + e1*w mod q
resp = json.loads(r.recvline())
print(resp)
a = resp["a"]
y = resp["y"]

e1 = 1234567890
r.sendline(json.dumps({"e": e1}).encode())

resp = json.loads(r.recvline())
print(resp)
z1 = resp["z"]

# Round 2: prover *reuses the same r* -> a2 == a. We pick a different e2 and
# get z2 = r + e2*w mod q. Two accepting transcripts sharing a commitment is
# exactly the special-soundness extractor setup.
resp = json.loads(r.recvline())
print(resp)
a2 = resp["a2"]
assert a2 == a, "commitment was not reused -- extraction assumption broken"

e2 = 987654321
r.sendline(json.dumps({"e": e2}).encode())

resp = json.loads(r.recvline())
print(resp)
z2 = resp["z2"]

# z1 - z2 = (e1 - e2)*w mod q  =>  w = (z1 - z2) * (e1 - e2)^-1 mod q
w = ((z1 - z2) * pow(e1 - e2, -1, q)) % q

assert pow(g, w, p) == y, "extraction failed -- recovered w does not match public y"
body = long_to_bytes(w)
print(body)
