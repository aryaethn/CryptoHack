"""
Armory -- Shamir's scheme, but the (minimum=3) polynomial's coefficients
are derived from the secret via a hash chain: coefs[0]=secret,
coefs[i]=sha256(coefs[i-1]), and poly = coefs[:3]. Each share's x-coordinate
is *also* one of these hash-chain values (x_i = coefs[i]).

The threshold is meaningless here: the very first share gives us x_1 =
coefs[1] directly. Since coefs[2] = sha256(coefs[1]) is fully determined by
coefs[1] alone (no dependency on the secret except through coefs[1], which
we already have), we can recompute coefs[2] ourselves -- recovering the
entire quadratic *except* the constant term (the secret). One point (x_1,
y_1) is then enough to solve the resulting single linear equation for
coefs[0] = secret.
"""
import hashlib
import re

from Crypto.Util.number import long_to_bytes

PRIME = 77793805322526801978326005188088213205424384389488111175220421173086192558047

with open("share_armory.txt") as f:
    x1, y1 = map(int, re.findall(r"\d+", f.read()))

coef1 = x1
coef2 = int.from_bytes(hashlib.sha256(coef1.to_bytes(32, "big")).digest(), "big")

secret = (y1 - coef1 * x1 - coef2 * pow(x1, 2, PRIME)) % PRIME
print(long_to_bytes(secret).decode())
