"""
Toshi's Treasure -- Shamir's Secret Sharing (5-of-6, Wikipedia's textbook
implementation, PRIME = 2**521 - 1, the 13th Mersenne prime).

The fatal flaw: with plain (non-verifiable) Shamir sharing, the combiner
reconstructs the secret via Lagrange interpolation at x=0:

    secret = sum_i y_i * L_i(0)   (mod PRIME)

where the Lagrange coefficients L_i(0) depend only on the *public* set of
x-coordinates in play, not on any of the y-values. So if the other 4
participants resubmit the same (unknown to us) real shares across rounds,
their combined contribution K = sum_{i != us} y_i * L_i(0) is a FIXED
constant. Our own contribution is y_us * L_us(0), entirely under our
control. That makes the reconstructed secret an affine function of the one
share we submit -- and an affine function with a single unknown (K) is
fully determined by a single data point.

Plan:
  1. Submit any throwaway fake share for our x -- the server still runs the
     combiner and reveals the (garbage) resulting "privkey". That one
     reveal, together with the known Lagrange coefficient for our position,
     is enough to solve for K.
  2. Craft a second fake share that lands the combined secret exactly on
     the known private key for our own $1k wallet (from hyper_privkey.txt)
     -- confirms the attack and matches the challenge's narrative "prank".
  3. Finally, compute the *real* secret using our real share (given to us
     at connection time) plus the now-known K, and submit it as our
     private key to unlock the actual treasure wallet.
"""
import json

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13384

PRIME = 2**521 - 1
OUR_X = 6
OTHER_XS = [2, 3, 4, 5]


def lagrange_coeff_at_zero(xi, xs, prime):
    num, den = 1, 1
    for xj in xs:
        if xj == xi:
            continue
        num = (num * (-xj)) % prime
        den = (den * (xi - xj)) % prime
    return (num * pow(den, -1, prime)) % prime


L6 = lagrange_coeff_at_zero(OUR_X, OTHER_XS + [OUR_X], PRIME)

with open("hyper_privkey.txt") as f:
    target = int(f.read().split('"')[1], 16)

r = remote(HOST, PORT)


def recv_json():
    return json.loads(r.recvline())


our_y = None
for _ in range(5):
    j = recv_json()
    print(j)
    if j.get("sender") == "your_share":
        our_y = int(j["y"], 16)

# round 1: throwaway fake share, just to learn K from the revealed combine
fake1 = 0xDEAD
r.sendline(json.dumps({"x": OUR_X, "y": hex(fake1)}).encode())
resp1 = recv_json()
print(resp1)
secret1 = int(resp1["privkey"], 16)
K = (secret1 - fake1 * L6) % PRIME

for _ in range(2):
    print(r.recvline())

# round 2: fake share landing exactly on the $1k wallet's known private key
Linv = pow(L6, -1, PRIME)
fake2 = ((target - K) * Linv) % PRIME
r.sendline(json.dumps({"x": OUR_X, "y": hex(fake2)}).encode())
resp2 = recv_json()
print(resp2)
assert int(resp2["privkey"], 16) == target

for _ in range(2):
    print(r.recvline())

# final: real secret using our real share, to unlock the actual treasure
real_secret = (K + our_y * L6) % PRIME
r.sendline(json.dumps({"privkey": hex(real_secret)}).encode())
print(r.recvline())

r.close()
