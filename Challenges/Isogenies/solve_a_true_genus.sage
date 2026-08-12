#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "A True Genus" (175)

"If only Gauss were here..."

The scheme is a CSIDH-style class group action used as a bit-commitment: for
each bit of a 64-bit SECRET the challenger publishes a triple (EA, EB, EC),
where EC is the true Diffie-Hellman shared curve when the bit is 1, and an
unrelated curve when it is 0.  Recovering SECRET means solving 63 instances of
the *decisional* Diffie-Hellman problem for the class group action.

Why this instance is broken: p = 1 mod 4
----------------------------------------
Any supersingular E/F_p has p+1 rational points and pi^2 + p = 0, so
O = End_{F_p}(E) has discriminant

    -4p            if p = 1 mod 4,
    -p  or  -4p    if p = 3 mod 4.

Genus theory: writing D = -4n, the number of genera is 2^(mu-1) with mu = r
when n = 3 mod 4 and mu = r+1 when n = 1 mod 4, where r counts the odd primes
dividing n.  Here n = p is prime, so r = 1 and

    p = 3 mod 4  ->  mu = 1  ->  ONE genus     -> no character, nothing to do
    p = 1 mod 4  ->  mu = 2  ->  TWO genera    -> one non-trivial character

Real CSIDH takes p = 3 mod 4 and is therefore immune.  This challenge sets
p = 2 * prod(ls) - 1 with all ls odd, which forces p = 1 mod 4 -- deliberately
manufacturing the one genus character that breaks DDH.  That is the "Gauss"
hint: genus theory of binary quadratic forms.

The two assigned characters of D = -4p are the Legendre character mod p and
delta (the class of the norm mod 4).  The character relation makes them
coincide on cl(O), so it suffices to compute delta.

Reading the character off the exponent vector is easy:

    chi([l_i]) = (l_i | p) = (-1)^((l_i - 1)/2)

(the two agree by quadratic reciprocity because p = 1 mod 4).  So chi is +1 for
l = 1 mod 4 and -1 for l = 3 mod 4.  This is exactly what source.sage's
redacted `backdoor` computes -- `secret_marks` is the vector of Gauss's
assigned characters, "marks" being the classical terminology, and
b = prod(m_i^e_i) is chi applied to the private exponent vector.

That also makes the distinguisher *deterministic* rather than statistical: the
loop `while backdoor(privC) == t` guarantees the decoy has the wrong character,
so

    bit = 1  <=>  chi(EC) = chi(EA) * chi(EB).

Evaluating chi on a curve: Castryck-Sotakova-Vercauteren, Theorem 10
--------------------------------------------------------------------
The hard part is computing chi([a]) from the curves alone.  It is *not* any
Legendre symbol of the usual invariants -- I checked empirically against
labelled data and it cannot be: [l_11] and [l_17] give curves with identical
(a4, a6, x0, j) quadratic residuosity but opposite characters.

The reason is that delta is a **quartic** residue symbol.  From
"Breaking the DDH problem for class group actions using genus theory"
(Castryck, Sotakova, Vercauteren, CRYPTO 2020, Theorem 10):

    Let q = 1 mod 4, and E, E' / F_q have the same endomorphism ring and trace
    t = 0 mod 4, connected by [a].  Writing the curves with their unique
    rational 2-torsion point moved to (0,0),

        E  : y^2 = x^3 + a x^2 + b x        E' : y^2 = x^3 + a' x^2 + b' x

    then   delta([a]) = (b'/b)^((q-1)/4).

Supersingular curves over F_p have t = 0, so t = 0 mod 4 holds.  Putting the
2-torsion at the origin is just a shift: if x0 is the unique root of
x^3 + a4 x + a6 then substituting x -> x + x0 gives

    b = 3*x0^2 + a4 = f'(x0),

the same quantity that appears in Velu's formulas for the 2-isogeny.

Two structural facts fall out of the theorem, and both hold in the data:

  * b is always a NON-square.  (If it were a square, one of a +- 2*sqrt(b)
    would be square and E would have a rational point of order 4, impossible
    since #E(F_p) = 2 mod 4.)  So b^((p-1)/4) is a primitive 4th root of unity,
    and the ratio of two of them is +-1 -- the character.
  * Because b is only defined up to u^4, b^((p-1)/4) is a genuine invariant:
    (u^4)^((p-1)/4) = u^(p-1) = 1.

This script verifies Theorem 10 against ground truth before using it: it
computes [l_i] * E0 for each of the 29 primes with the real group action and
checks delta equals the known mark (-1)^((l_i-1)/2).
"""

import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

proof.all(False)

# ---------------------------------------------------------------------------
# Parameters (verbatim from source.sage)
# ---------------------------------------------------------------------------

ls = list(primes(3, 112)) + [139]
p = 2 * prod(ls) - 1
max_exp = ceil((sqrt(p) ** (1 / len(ls)) - 1) / 2)
Fp = GF(p)
Fp2 = GF(p**2, names="w", modulus=[3, 0, 1])
base = EllipticCurve(Fp2, [0, 1])
Rx = PolynomialRing(Fp, "X")
X = Rx.gen()

assert is_prime(p) and p % 4 == 1, "the whole attack needs p = 1 mod 4"
assert p % 3 == 2, "y^2 = x^3 + 1 must be supersingular"
print(f"p has {p.nbits()} bits,  p = 1 mod 4,  {len(ls)} primes,  max_exp = {max_exp}")
print("D = -4p  ->  mu = 2  ->  2 genera  ->  exactly one non-trivial character\n")


# ---------------------------------------------------------------------------
# The class group action (as in source.sage), used only to validate Theorem 10
# ---------------------------------------------------------------------------

def action(pub, priv):
    E = pub
    es = priv[:]
    while any(es):
        E._order = (p + 1) ** 2
        P = E.lift_x(Fp.random_element())
        s = +1 if P.xy()[1] in Fp else -1
        k = prod(l for l, e in zip(ls, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(ls, es)):
            if sign(e) != s:
                continue
            Q = k // l * P
            if not Q:
                continue
            Q._order = l
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            es[i] -= s
            k //= l
    return E


# ---------------------------------------------------------------------------
# CSV Theorem 10:  delta([a]) = (b'/b)^((p-1)/4)
# ---------------------------------------------------------------------------

def quartic(a4, a6):
    """
    Move the unique rational 2-torsion point to (0,0) and return b^((p-1)/4),
    a primitive 4th root of unity.  b = f'(x0) with x0 the rational 2-torsion.
    """
    a4, a6 = Fp(a4), Fp(a6)
    roots = (X**3 + a4 * X + a6).roots(multiplicities=False)
    assert len(roots) == 1, f"expected a unique rational 2-torsion point, got {len(roots)}"
    b = 3 * roots[0]**2 + a4
    assert not b.is_square(), "Theorem 10 requires b to be a non-square"
    return b ** ((p - 1) // 4)


B_BASE = quartic(0, 1)
assert B_BASE**2 == Fp(-1), "b^((p-1)/4) should be a primitive 4th root of unity"


def chi(a4, a6):
    """The genus character of the class connecting E0 to y^2 = x^3 + a4 x + a6."""
    d = quartic(a4, a6) / B_BASE
    assert d in (Fp(1), Fp(-1))
    return 1 if d == Fp(1) else -1


# --- validate against ground truth -----------------------------------------

print("[*] validating Theorem 10 against the known marks ...")
bad = []
for idx, l in enumerate(ls):
    pv = [0] * len(ls)
    pv[idx] = 1
    E = action(base, pv)
    mark = 1 if l % 4 == 1 else -1
    if chi(E.a4(), E.a6()) != mark:
        bad.append(l)
assert not bad, f"Theorem 10 failed for l in {bad}"
print(f"    [ok] delta = (-1)^((l-1)/2) for all {len(ls)} primes\n")


# ---------------------------------------------------------------------------
# Break DDH on every challenge triple
# ---------------------------------------------------------------------------

blob = json.loads(Path("output_true_genus.txt").read_text())
data = blob["challenge_data"]
print(f"[*] {len(data)} challenge triples -> {len(data)} bits of SECRET")


def curve_chi(entry):
    a4, a6 = entry["a4"], entry["a6"]
    assert a4[1] == 0 and a6[1] == 0, "curve is not defined over F_p"
    return chi(a4[0], a6[0])


bits = []
for ch in data:
    cA, cB, cC = (curve_chi(ch[k]) for k in ("EA", "EB", "EC"))
    bits.append(1 if cC == cA * cB else 0)

SECRET = sum(b << i for i, b in enumerate(bits))
print(f"    bits (LSB first): {''.join(map(str, bits))}")
print(f"    SECRET = {SECRET}")
assert SECRET.nbits() == len(data), "top bit should be set"


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

key = SHA256.new(int(SECRET).to_bytes(8, "big")).digest()[:128]
flag = unpad(AES.new(key, AES.MODE_CBC, bytes.fromhex(blob["iv"]))
             .decrypt(bytes.fromhex(blob["ct"])), 16)

print()
print(f"FLAG = {flag.decode()}")
