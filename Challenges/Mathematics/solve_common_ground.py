"""
Common Ground -- key = sha256(long_to_bytes(g))[:16], where
g = gcd(N**a - 1, N**b - 1), for a 1024-bit prime N and ~2048-bit random
a, b. Computing N**a and N**b directly, let alone their gcd, is hopeless
(a, b are far too large).

But there's no need: for any integer N > 1 and positive integers a, b,

    gcd(N**a - 1, N**b - 1) == N**gcd(a, b) - 1

(standard identity -- same proof idea as the Euclidean algorithm itself,
via N**a - 1 = (N**b - 1) * N**(a-b) + (N**(a-b) - 1) when a > b). Since
a and b are handed to us directly in output.txt, gcd(a, b) is a single
cheap Euclidean-algorithm call, and it comes out tiny (2, here) even
though a and b themselves are enormous -- so g = N**gcd(a, b) - 1 is a
perfectly tractable computation too.
"""
import hashlib
import json
import math

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

with open("output_common_ground.txt") as f:
    lines = f.read().splitlines()

N = int(lines[0].split("=")[1])
a = int(lines[1].split("=")[1])
b = int(lines[2].split("=")[1])
data = json.loads(lines[3])

g = pow(N, math.gcd(a, b)) - 1
key = hashlib.sha256(long_to_bytes(g)).digest()[:16]

cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex(data["iv"]))
pt = unpad(cipher.decrypt(bytes.fromhex(data["ct"])), 16)
print(pt.decode())
