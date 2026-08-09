#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "CSIDH Key Exchange" (90)

Implement CSIDH-512 end to end: derive both public keys from the given private
exponent vectors, complete the exchange from each side, check the two shared
secrets agree, and decrypt the flag.

The protocol
------------
Public parameters: the odd primes l_0..l_73, p = 4 * prod(l_i) - 1, and the
starting curve E0 : y^2 = x^3 + x, i.e. M_0.

A private key is an exponent vector e in [-3,3]^74, denoting the ideal class
[l_0]^{e_0} ... [l_73]^{e_73}.  A public key is the single Montgomery
coefficient A of the curve that class sends E0 to.

    Alice:  A_pub = a * E0          Bob:  B_pub = b * E0
    Alice:  a * B_pub               Bob:  b * A_pub

and because the class group is abelian both sides land on (a+b) * E0.  The
shared secret is that curve's Montgomery coefficient.

Note how much smaller this is than SIDH: a public key is one element of F_p,
about 64 bytes, and *nothing else* is transmitted.  No torsion point images --
which is exactly why the 2022 attacks that destroyed SIDH do not apply.  The
price is speed and a subtler quantum security story (Kuperberg's algorithm
gives a subexponential quantum attack on the abelian hidden-shift problem, so
CSIDH parameters must be chosen far more conservatively than SIDH's were).

Recovering the Montgomery coefficient
-------------------------------------
Velu hands back a curve in some Weierstrass model; CSIDH needs the Montgomery
coefficient.  Brute-forcing A (fine at p = 419 in the earlier challenges) is
hopeless at 511 bits, so we invert the transformation properly.

M_A : y^2 = x^3 + Ax^2 + x becomes, under x -> x - A/3,

    y^2 = x^3 + (1 - A^2/3) x + (2A^3/27 - A/3),

and the Montgomery point x_M = 0 (the rational 2-torsion point) maps to
x_W = A/3.  So given E : y^2 = x^3 + ax + b with rational 2-torsion (alpha, 0),

    A = 3*alpha / sqrt(3*alpha^2 + a).

This is invariant under the Weierstrass scaling (a,b) -> (u^4 a, u^6 b), since
alpha -> u^2 alpha and sqrt(3 alpha^2 + a) -> u^2 sqrt(...), so it may be
applied to any short Weierstrass model of E.  Two cautions, both of which bit
during development:

  * E.a4()/E.a6() are NOT the short-Weierstrass coefficients when a2 != 0, and
    a Montgomery curve has a2 = A.  Take E.short_weierstrass_model() first.
  * sqrt is defined only up to sign, and the two signs give A and -A, which are
    quadratic twists and genuinely different CSIDH curves.  Pick the sign by
    testing which one is F_p-isomorphic to E.

Since E(F_p) is cyclic of order p+1 = 4*prod(l_i), its 2-torsion is Z/2: there
is exactly one rational alpha, so the recovered A is unique.
"""

import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

# ---------------------------------------------------------------------------
# Parameters (verbatim from source_csidh.sage)
# ---------------------------------------------------------------------------

ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])                    # M_0

a_priv = [-1, -2, -3, -3, -2, -3, -3, 0, 2, -1, 2, -1, -2, -3, 1, 2, 1, 2, 0, 0, 1, -1, 0, 2, -1, 0, 0, 0, 1, -1, -3, 1, -1, -3, -3, 2, 2, 1, -1, -1, 1, 0, 1, 1, 1, -2, 2, 2, -2, -2, 0, 0, 2, 0, -1, -3, -2, -2, 0, -1, -3, -1, -2, -3, -2, 2, 1, 1, -2, 0, 1, -1, -3, 2]
b_priv = [-1, -1, 0, 1, 2, 0, 2, -1, -3, 1, 0, -2, -2, 2, -1, -2, -3, -3, -3, 2, 2, 2, -2, -1, 1, -2, 0, -3, -1, 1, -1, -1, -3, -1, -2, 1, -1, -2, -3, 1, 0, -1, 1, 2, 2, 0, 0, -1, -2, -2, 1, -1, 1, 1, 1, 1, 0, 0, 0, -3, -2, -1, 2, 0, -3, -2, 1, 1, -2, -1, -1, 2, 0, 1]

iv_hex = 'daf6cd181775664b099609789fb564c9'
ct_hex = '3dd92e255c8e677f4a92226d09f56e2b2f567052ffd4f6f60200018454a83affc2e694c2bf2ad27da38f7f49b6e89928'

assert is_prime(p) and p % 4 == 3
assert E0.is_supersingular() and E0.order() == p + 1
assert E0.abelian_group().invariants() == (p + 1,), "E0(F_p) must be cyclic"
assert not F(-1).is_square()
assert len(ells) == len(a_priv) == len(b_priv) == 74

print(f"CSIDH-512:  p has {p.nbits()} bits,  {len(ells)} primes")
print(f"  |a| = {sum(abs(e) for e in a_priv)} steps,  "
      f"|b| = {sum(abs(e) for e in b_priv)} steps\n")

Rx = PolynomialRing(F, 'x')
x = Rx.gen()


# ---------------------------------------------------------------------------
# Montgomery bookkeeping
# ---------------------------------------------------------------------------

def curve(A):
    return EllipticCurve(F, [0, A, 0, 1, 0])     # M_A : y^2 = x^3 + Ax^2 + x


def montgomery_A(E):
    """The unique A with M_A isomorphic to E over F_p."""
    Es = E.short_weierstrass_model()
    a, b = Es.a4(), Es.a6()
    for alpha in (x**3 + a * x + b).roots(F, multiplicities=False):
        t = 3 * alpha**2 + a
        if not t.is_square():
            continue
        A = 3 * alpha / t.sqrt()
        for cand in (A, -A):                     # the two signs are twists
            if E.is_isomorphic(curve(cand)):
                return cand
    raise ValueError("no Montgomery coefficient found")


assert montgomery_A(E0) == 0


# ---------------------------------------------------------------------------
# The group action
# ---------------------------------------------------------------------------

def step(A, ell):
    """Forward: the unique F_p-rational ell-isogeny.  This is the action of [l]."""
    E = curve(A)
    cofactor = (p + 1) // ell
    while True:
        P = cofactor * E.random_point()
        if P.order() == ell:
            break
    phi = E.isogeny(P)
    assert phi.degree() == ell
    return montgomery_A(phi.codomain())


def back_step(A, ell):
    """Backward: the action of [lbar] = [l]^-1, via the twist (M_A)^t = M_-A."""
    return -step(-A, ell)


def group_action(A, evec, label=""):
    """Apply [l_0]^e_0 ... [l_k]^e_k to M_A."""
    t0 = time.time()
    total = sum(abs(e) for e in evec)
    done = 0
    for ell, e in zip(ells, evec):
        for _ in range(abs(e)):
            A = step(A, ell) if e > 0 else back_step(A, ell)
            done += 1
            if done % 25 == 0:
                print(f"    [{label}] {done}/{total} steps  ({time.time()-t0:.0f}s)",
                      flush=True)
    print(f"    [{label}] done, {total} steps in {time.time()-t0:.0f}s", flush=True)
    return A


# ---------------------------------------------------------------------------
# Key exchange
# ---------------------------------------------------------------------------

print("[*] Alice's public key ...")
A_pub = group_action(F(0), a_priv, "alice pub")
print(f"    A_pub = {A_pub}\n")

print("[*] Bob's public key ...")
B_pub = group_action(F(0), b_priv, "bob pub")
print(f"    B_pub = {B_pub}\n")

print("[*] Alice applies her key to Bob's curve ...")
sec_a = group_action(B_pub, a_priv, "alice sec")
print("[*] Bob applies his key to Alice's curve ...")
sec_b = group_action(A_pub, b_priv, "bob sec")

print(f"\n  Alice's shared secret : {sec_a}")
print(f"  Bob's shared secret   : {sec_b}")
assert sec_a == sec_b, "the two sides disagree -- the action did not commute"
print("  [ok] both parties agree")

# The challenge's own phrasing: the result is the action of the SUM of the
# two exponent vectors applied to E0.  Verified independently.
print("\n[*] cross-check: acting with (a + b) directly on E0 ...")
sec_sum = group_action(F(0), [ea + eb for ea, eb in zip(a_priv, b_priv)], "a+b")
assert sec_sum == sec_a, "(a+b)*E0 differs from a*(b*E0)"
print("  [ok] (a + b) * E0 equals a * (b * E0)")

shared_secret = sec_a


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
flag = unpad(AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex)).decrypt(bytes.fromhex(ct_hex)), 16)

print()
print(f"FLAG = {flag.decode()}")
