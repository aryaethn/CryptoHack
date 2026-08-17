#!/usr/bin/env python3
"""
CryptoHack -- ZKP -- "Let's prove it again"   (server source: 13431.py)

The server hands out Schnorr proofs of knowledge of x = self.FLAG:

    p = self.getPrime(BITS)          # BITS = 1024, from self.R
    y = pow(g, self.FLAG, p)
    self.refresh()                   # R reseeded with os.urandom(8)
    t = pow(g, self.v, p)
    c = H( t ^ y ^ g ^ self.R.randint(2, BITS) )
    r = (self.v - c * self.FLAG) % (p - 1)

---------------------------------------------------------------------------
The bug: the Schnorr nonce is generated ONCE
---------------------------------------------------------------------------
    self.v = self.R.getrandbits(BITS >> 1)      # in __init__, never again

Every proof reuses the same v.  Two proofs under the SAME modulus give

    r1 - r2 = (v - c1*x) - (v - c2*x) = (c2 - c1) * x   (mod p-1)

and x drops straight out.  This is the classic ECDSA/Schnorr repeated-nonce
break; the ZK property is irrelevant once the nonce is static.

Three things have to be arranged to use it.

1. FORCE TWO PROOFS TO SHARE p.  p comes from self.R, and the "refresh"
   option lets us set the seed: R = random.Random(self.nonce + seed), with
   the nonce printed in the banner.  Replay the same seed twice and both
   proofs use the same p (and hence the same t and y -- a free self-check).

   Turn economy: only get_proof consumes a turn (max_turns = 4), but refresh
   demands your_turn >= 2 while a get_proof only bumps it by 1.  So each
   seed-controlled proof costs one throwaway proof first:

       get_proof(throwaway) -> refresh(S) -> get_proof(A)
       get_proof(throwaway) -> refresh(S) -> get_proof(B)

   Exactly 4 turns.  It fits with nothing to spare.

2. RECOVER c.  The transcript hides the randint, but randint(2, BITS) with
   BITS = 1024 has only 1023 outcomes, and t, y, g are all returned.  Try
   every k and keep the one satisfying t == g^r * y^c (mod p).  (The previous
   attempt in this repo dismissed this as "unpredictable" and went hunting for
   smooth p-1 instead -- it is a 1023-way brute force.)

3. KNOW p EXACTLY.  getPrime loops `R.getrandbits(N) | 1` until isPrime, and
   isPrime *also* draws from R through its randfunc -- so replaying it needs
   pycryptodome's Miller-Rabin to consume randomness identically to the
   server's.  Sidestep that entirely: search seeds until the FIRST candidate
   is already prime.  Then p = R.getrandbits(1024) | 1 with no dependence on
   isPrime's internals at all.  About 1 seed in 355 works (prime density among
   odd 1024-bit integers), so the search is seconds.

Finally undo the wrapping: self.FLAG = bytes_to_long(xor_nonce(
add_random_nonprintable(FLAG), nonce)) -- xor bytes 7..37 with the nonce
again, then drop the single injected non-printable byte.
"""

import json
import random
import string
import sys
from hashlib import sha3_256
from math import gcd

from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime

HOST, PORT = "socket.cryptohack.org", 13431
BITS = 2 << 9          # 1024
g = 2
PADDED_LEN = 39        # 38-byte flag + 1 injected byte
NONCE_LEN = 31


def find_first_candidate_prime_seed(nonce, start=0, limit=200000):
    """Seed whose very first getPrime candidate is prime -> p is unambiguous."""
    for i in range(start, limit):
        seed = i.to_bytes(8, "big")
        cand = random.Random(nonce + seed).getrandbits(BITS) | 1
        if isPrime(cand):
            return seed, cand
    raise RuntimeError("no suitable seed found")


def recover_c(t, y, r, p):
    """randint(2, BITS) has 1023 outcomes; the Schnorr equation picks the one."""
    gr = pow(g, r, p)
    for k in range(2, BITS + 1):
        blob = long_to_bytes(t ^ y ^ g ^ k)
        c = bytes_to_long(sha3_256(blob).digest())
        if gr * pow(y, c, p) % p == t:
            return c, k
    raise RuntimeError("no k in [2, %d] reproduces the proof" % BITS)


def solve_congruence(e, d, m, y, p):
    """e*x = d (mod m); return the branch that is a valid 39-byte discrete log."""
    h = gcd(e, m)
    if d % h:
        raise RuntimeError("inconsistent congruence")
    m2 = m // h
    x0 = (d // h) * pow(e // h, -1, m2) % m2
    for j in range(min(h, 1 << 16)):
        x = x0 + j * m2
        if x < (1 << (8 * PADDED_LEN)) and pow(g, x, p) == y:
            return x
    raise RuntimeError("no valid branch of the congruence")


def unwrap(F, nonce):
    b = long_to_bytes(F, PADDED_LEN)
    middle = bytes(u ^ v for u, v in zip(b[7:PADDED_LEN - 1], nonce))
    padded = b[:7] + middle + b[PADDED_LEN - 1:]
    return bytes(ch for ch in padded if chr(ch) in string.printable)


# --------------------------------------------------------------------------
# transports
# --------------------------------------------------------------------------
class RemoteSession:
    def __init__(self):
        from pwn import remote
        self.r = remote(HOST, PORT)
        self.r.recvline()                                   # greeting
        line = self.r.recvline().decode()
        self.nonce = bytes.fromhex(line.split(":")[1].strip())

    def send(self, obj):
        self.r.sendline(json.dumps(obj).encode())
        return json.loads(self.r.recvline())


class LocalSession:
    """Drives 13431.py's Challenge in-process, with utils.listener stubbed."""

    def __init__(self):
        import types, importlib.util, os
        stub = types.ModuleType("utils")
        stub.listener = types.SimpleNamespace(start_server=lambda *a, **k: None)
        sys.modules.setdefault("utils", stub)
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "13431.py")
        spec = importlib.util.spec_from_file_location("chal13431", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.c = mod.Challenge()
        self.nonce = self.c.nonce

    def send(self, obj):
        return self.c.challenge(obj)


def main():
    local = "--local" in sys.argv
    s = (LocalSession if local else RemoteSession)()
    print("[*] nonce = %s" % s.nonce.hex())

    seed, p = find_first_candidate_prime_seed(s.nonce)
    print("[*] seed = %s -> p (first candidate, prime) = %d bits"
          % (seed.hex(), p.bit_length()))

    proofs = []
    for label in ("A", "B"):
        assert "y" in s.send({"option": "get_proof"}), "throwaway proof failed"
        resp = s.send({"option": "refresh", "seed": seed.hex()})
        assert "msg" in resp, resp
        pr = s.send({"option": "get_proof"})
        assert "y" in pr, pr
        proofs.append(pr)
        print("[+] proof %s: t=%d... r=%d..." % (label, pr["t"] % 10**8, pr["r"] % 10**8))

    A, B = proofs
    assert A["t"] == B["t"] and A["y"] == B["y"], "moduli differ; seed replay failed"
    assert A["r"] != B["r"], "identical challenges; reconnect and retry"
    y, t = A["y"], A["t"]
    assert pow(g, 1, p) and y < p and t < p, "p looks wrong"

    cA, kA = recover_c(t, y, A["r"], p)
    cB, kB = recover_c(t, y, B["r"], p)
    print("[+] recovered randints: k_A=%d, k_B=%d" % (kA, kB))

    F = solve_congruence((cB - cA) % (p - 1), (A["r"] - B["r"]) % (p - 1),
                         p - 1, y, p)
    print("[+] secret exponent recovered (%d bits)" % F.bit_length())
    print("[+] FLAG: %s" % unwrap(F, s.nonce).decode())


if __name__ == "__main__":
    main()
