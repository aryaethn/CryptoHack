#!/usr/bin/env sage
#
# CryptoHack -- Elliptic Curves / Parameter Choice 2 -- "An Evil Twisted Mind"
# socket.cryptohack.org:13418   (source: 13418.py)
#
# ---------------------------------------------------------------------------
# The setup
# ---------------------------------------------------------------------------
# The server runs a Brier-Joye x-only ladder for y^2 = x^3 + ax + b, a = -3,
# but *modulo a composite* N = p*q (two 192-bit primes).  We may submit ONE
# x-coordinate x0 and get back x([d]P) mod N; d = privkey is folded into
# [0, order/2] where order = #E(F_p), so d < 2^190.6.  60 second timeout.
#
# Two independent weaknesses compose:
#
#  1. x-only input means we never prove x0 is on E.  If x0^3+ax0+b is a
#     non-square, the "point" lives on the quadratic twist E', and the ladder
#     happily computes there -- the classic invalid-curve/twist attack.
#
#  2. N is composite, so by CRT the single ladder run is really TWO runs, one
#     mod p and one mod q, on curves we get to choose *independently*.  One
#     query therefore yields d mod (subgroup order at p) AND d mod (at q).
#
# Orders (computed, not guessed):
#     #E (F_p) = 4782850957738000717885060297297408935631027604045525430677  (prime)
#     #E'(F_p) = 1965293129 * 3945014767 * 6911909839
#                * 89250943167080667773197903811
#     #E (F_q) = 4796464665474109238546017500248864844101938253734108186207  (prime)
#     #E'(F_q) = 17 * 1789 * 8984179 * 9381319 * 83816652113
#                * 22324892568046125682687618733
#
# Both curves have prime order -- staying on E gives nothing.  Both *twists*
# are partly smooth, and
#
#     M_p * M_q = 2^95.44 * 2^97.44 = 2^192.88  >  order/2 = 2^190.61
#
# so Pohlig-Hellman on the twist at p and at q pins d down completely, with no
# brute-force tail.  We pick x0 by CRT so that it is the x-coordinate of a
# point of order exactly M_p on E'(F_p) and of order exactly M_q on E'(F_q).
#
# ---------------------------------------------------------------------------
# Working on the twist without GF(p^2)
# ---------------------------------------------------------------------------
# For a non-square u mod p, the twist has an F_p-rational model
#     E~ : y^2 = x^3 + a*u^2*x + b*u^3,      x_E = x_E~ / u.
# All arithmetic stays in GF(p), which is what keeps us inside the timeout.
#
# ---------------------------------------------------------------------------
# The sign ambiguity
# ---------------------------------------------------------------------------
# x([d]P) determines [d]P only up to sign, independently at p and at q, so we
# recover e_p = s_p*d mod M_p and e_q = s_q*d mod M_q with unknown signs.  A
# local check is useless here: all four CRT lifts produce the *same* x-only
# output, since x([c]P) = x([-c]P).  But get_flag is unlimited (only
# get_pubkey is capped), and d < M_p*M_q, so exactly one of the four lifts is
# d -- we just submit them all.  (d < M/2 halves it to two in practice.)
#
# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------
# The 60s clock starts at connect, so every table is built BEFORE connecting:
# the baby-step tables of a custom BSGS depend only on the base point, which
# we choose ourselves.  Online work is giant steps only, ~5s total.

from sage.all import *
import json, socket, time, sys

HOST, PORT = "socket.cryptohack.org", 13418

# ---- challenge parameters (13418.py) --------------------------------------
N = Integer(22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651)
a = Integer(-3)
b = Integer(2697448053935541741976221051345108825177671050689533270507)
order = Integer(4782850957738000717885060297297408935631027604045525430677)

p = Integer(4782850957738000717885060297350722702854694354378697989111)
q = Integer(4796464665474109238546017500238174976861701183900526078141)
assert p * q == N and p.is_prime() and q.is_prime()


# ---------------------------------------------------------------------------
# exact copy of the server's x-only ladder (for the local self-test)
# ---------------------------------------------------------------------------
def scalarmult(scalar, x0, mod=None):
    mod = int(N if mod is None else mod)
    A, B, x0 = int(a) % mod, int(b) % mod, int(x0) % mod

    def dbl(P1):
        X1, Z1 = P1
        XX, ZZ = X1 * X1 % mod, Z1 * Z1 % mod
        t = 2 * ((X1 + Z1) ** 2 - XX - ZZ) % mod
        aZZ = A * ZZ % mod
        return (((XX - aZZ) ** 2 - 2 * B * t * ZZ) % mod,
                (t * (XX + aZZ) + 4 * B * ZZ * ZZ) % mod)

    def diffadd(P1, P2):
        X1, Z1 = P1
        X2, Z2 = P2
        X1Z2, X2Z1, Z1Z2 = X1 * Z2 % mod, X2 * Z1 % mod, Z1 * Z2 % mod
        T = (X1Z2 + X2Z1) * (X1 * X2 + A * Z1Z2) % mod
        Z3 = (X1Z2 - X2Z1) ** 2 % mod
        return ((2 * T + 4 * B * Z1Z2 * Z1Z2 - x0 * Z3) % mod, Z3)

    scalar = int(scalar)
    R0, R1 = (x0, 1), None
    R1 = dbl(R0)
    n = scalar.bit_length()
    pbit = bit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = (pbit + bit) % 2      # NB: '^' is exponentiation in .sage files
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1)
        R0 = dbl(R0)
        pbit = bit
    if bit:
        R0 = R1
    if R0[1] % mod == 0:
        return None
    return R0[0] * pow(R0[1], -1, mod) % mod


# ---------------------------------------------------------------------------
# BSGS with an offline baby-step table (keyed on the x-coordinate)
# ---------------------------------------------------------------------------
class BabyTable:
    """Precomputed baby steps for dlog in <P_l>, |P_l| = ell (prime)."""

    def __init__(self, P_l, ell):
        self.P, self.ell = P_l, Integer(ell)
        self.m = isqrt(self.ell) + 1
        tbl, T = {}, P_l.curve()(0)
        for j in range(self.m):
            tbl[-1 if T.is_zero() else int(T[0])] = j
            T += P_l
        self.tbl = tbl              # x([j]P) -> j   (unique: j < sqrt(ell))
        self.S = self.m * P_l

    def log(self, Q_l):
        T = Q_l
        for i in range(self.m + 1):
            j = self.tbl.get(-1 if T.is_zero() else int(T[0]))
            if j is not None:
                for e in (i * self.m + j, i * self.m - j):
                    e = Integer(e) % self.ell
                    if e * self.P == Q_l:
                        return e
            T -= self.S
        raise ValueError("BSGS failed")


class Side:
    """Everything we precompute for one prime factor of N."""

    def __init__(self, r, smooth_factors, cofactor):
        self.r = Integer(r)
        F = GF(self.r)
        u = F(-1)
        while u.is_square():
            u = F.random_element()
        self.u = u
        self.E = EllipticCurve(F, [a * u ** 2, b * u ** 3])
        assert self.E.order() == 2 * self.r + 2 - \
            EllipticCurve(F, [a, b]).order()

        self.M = prod(Integer(f) for f in smooth_factors)
        self.factors = [Integer(f) for f in smooth_factors]
        assert self.M * Integer(cofactor) == self.E.order()

        while True:                                   # base point of order M
            P = Integer(cofactor) * self.E.random_point()
            if P.order() == self.M:
                break
        self.P = P
        self.x0 = Integer(P[0] / u)                   # back to E's coordinates

        self.tables = {}
        for ell in self.factors:
            self.tables[ell] = BabyTable((self.M // ell) * P, ell)

    def dlog(self, pub):
        """pub = x([d]P) mod r  ->  e = +-d mod M."""
        Q = self.E.lift_x(self.u * GF(self.r)(pub))
        res, mods = [], []
        for ell in self.factors:
            res.append(self.tables[ell].log((self.M // ell) * Q))
            mods.append(ell)
        return crt(res, mods)


# ---------------------------------------------------------------------------
# network
# ---------------------------------------------------------------------------
class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)))  # Sage Integer -> int
        self.buf = b""

    def _line(self):
        while b"\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line

    def json(self):
        while True:
            line = self._line().strip()
            if line.startswith(b"{"):
                return json.loads(line)
            if line:
                print("   [server]", line.decode(errors="replace"))

    def send(self, obj):
        self.s.sendall((json.dumps(obj) + "\n").encode())


# ---------------------------------------------------------------------------
def main():
    local = "--local" in sys.argv

    t0 = time.time()
    print("[*] precomputing (before the clock starts)...")
    S_p = Side(p, [1965293129, 3945014767, 6911909839],
               89250943167080667773197903811)
    S_q = Side(q, [17, 1789, 8984179, 9381319, 83816652113],
               22324892568046125682687618733)
    M = S_p.M * S_q.M
    print("    M_p = 2^%.2f, M_q = 2^%.2f, M = 2^%.2f  >  order/2 = 2^%.2f"
          % (log(S_p.M, 2), log(S_q.M, 2), log(M, 2), log(order / 2, 2)))
    x0 = crt([S_p.x0, S_q.x0], [p, q])
    assert not GF(p)(x0 ** 3 + a * x0 + b).is_square()   # on the twist mod p
    assert not GF(q)(x0 ** 3 + a * x0 + b).is_square()   # on the twist mod q
    print("[*] precompute done in %.1fs" % (time.time() - t0))

    if local:
        secret = Integer(randint(0, order // 2))
        print("[*] LOCAL self-test, secret =", secret)
        pub = Integer(scalarmult(secret, x0))
        conn = None
    else:
        conn = Conn(HOST, PORT)
        conn.send({"option": "get_pubkey", "x0": int(x0)})
        pub = Integer(conn.json()["pubkey"])

    t1 = time.time()
    e_p = S_p.dlog(pub % p)
    e_q = S_q.dlog(pub % q)
    print("[*] both Pohlig-Hellmans done in %.1fs" % (time.time() - t1))

    cands = []
    for s_p in (1, -1):
        for s_q in (1, -1):
            c = crt([s_p * e_p % S_p.M, s_q * e_q % S_q.M], [S_p.M, S_q.M])
            if c not in cands:
                cands.append(c)
    cands.sort(key=lambda c: (c >= order // 2, c))   # d < order/2 first
    print("[*] %d candidates, online time so far %.1fs"
          % (len(cands), time.time() - t1))

    if local:
        print("[+] recovered:", secret in cands, " (secret is candidate #%d)"
              % (cands.index(secret) if secret in cands else -1))
        return

    for c in cands:
        conn.send({"option": "get_flag", "privkey": int(c)})
        resp = conn.json()
        print("   ", resp)
        if "flag" in resp:
            print("[+] privkey =", c)
            print("[+] FLAG:", resp["flag"])
            break


main()
