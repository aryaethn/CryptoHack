import json

from pwn import remote
from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13429

k1, k2 = 512, 128
R = 2 ** (2 * k2 + k1)  # = 2**768, the bound on the prover's random mask r

r = remote(HOST, PORT)
print(r.recvline().decode())

resp = json.loads(r.recvline())
print(resp)

# Girault's protocol never reduces z = r + e*flag modulo anything (there's no
# known order of g mod the RSA modulus N to reduce against). Soundness/ZK only
# holds for an *honest* verifier who samples e from the tiny prescribed range
# 0 <= e < 2^k2, which keeps e*flag << R so the mask r hides it completely.
#
# As a dishonest verifier we're free to send any e -- there's no bound check.
# Pick e >> R so the equation z = e*flag + r becomes an exact base-e
# two-digit representation with 0 <= r < R < e: flag is just z // e.
e = 2 ** 900
r.sendline(json.dumps({"e": e}).encode())

resp = json.loads(r.recvline())
print(resp)
z = resp["z"]

flag = z // e
print(long_to_bytes(flag))
