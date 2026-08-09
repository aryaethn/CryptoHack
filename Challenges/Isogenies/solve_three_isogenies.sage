#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Two Isogenies" (30) and "Three Isogenies" (35)

Goal
----
Given E : y^2 = x^3 + x over F_{p^2} with p = 2^18 * 3^13 - 1, and a kernel
generator K of small prime order l, compute the codomain E' = E/<K> of the
separable l-isogeny phi_l : E -> E', and report j(E').

Method
------
Velu's formulas (Sutherland's notes, Thm 5.13 / Velu 1971).

Let E : y^2 = x^3 + a4*x + a6 and let G be a finite subgroup of E of odd-or-even
order.  Write G \ {O} = G2 u S u (-S) where

    G2 = points of order 2 in G   (these satisfy Q = -Q),
    S  = one representative of each remaining pair {Q, -Q}.

Put R = G2 u S.  For each Q = (xQ, yQ) in R define

    gx_Q = 3*xQ^2 + a4          (= d/dx  of x^3 + a4 x + a6)
    gy_Q = -2*yQ                (= d/dy  of -(y^2), sign convention as in Velu)
    v_Q  = gx_Q                 if Q has order 2  (i.e. yQ = 0)
           2*gx_Q               otherwise
    u_Q  = (gy_Q)^2 = 4*yQ^2

Then with

    v = sum_{Q in R} v_Q,   w = sum_{Q in R} ( u_Q + xQ * v_Q )

the codomain is

    E' : y^2 = x^3 + (a4 - 5v) x + (a6 - 7w).

Intuition: the isogeny is x' = x + sum_{Q in G\{O}} (x - x_Q)^{-1}-type
correction terms; v and w are exactly the first two "power sums" of that
correction, and the constants 5 and 7 come from matching the Laurent expansion
of the Weierstrass p-function at O to the required order.

Why R and not all of G: the map is defined over the quotient, and Q and -Q
contribute identically, so summing over pairs (with the factor 2 in v_Q) avoids
double counting.  A 2-torsion point is its own inverse, hence has no partner and
gets no factor 2 -- that is the only case distinction in the formula.

For l = 3 the kernel is G = {O, K, -K} = {O, K, [2]K}, so R = {K}: a single term.

This script computes E' by hand with the formulas above and cross-checks against
Sage's EllipticCurveIsogeny.
"""

# ---------------------------------------------------------------------------
# Field and curve setup (as specified by the challenge)
# ---------------------------------------------------------------------------

p = 2**18 * 3**13 - 1
assert p % 4 == 3, "the modulus i^2 + 1 needs p = 3 mod 4 to be irreducible"
assert is_prime(p)

F = GF(p**2, names="i", modulus=[1, 0, 1])
i = F.gen()

E = EllipticCurve(F, [1, 0])          # y^2 = x^3 + x
a4, a6 = F(1), F(0)


# ---------------------------------------------------------------------------
# Velu's formulas
# ---------------------------------------------------------------------------

def velu_codomain(E, K):
    """
    Return the codomain E/<K> of the separable isogeny with kernel <K>,
    computed directly from Velu's formulas.

    E must be in short Weierstrass form y^2 = x^3 + a4*x + a6 (char != 2, 3).
    K is a point of finite order l >= 2.
    """
    a1, a2, a3, a4, a6 = E.a_invariants()
    assert (a1, a2, a3) == (0, 0, 0), "expected short Weierstrass form"

    l = K.order()

    # Build R = G2 u S : one representative per {Q, -Q} pair, plus 2-torsion.
    # Walking [1]K, [2]K, ..., [l-1]K and keeping a point only when its negative
    # has not been seen yet gives exactly that set.
    R, seen = [], set()
    Q = K
    for _ in range(l - 1):
        if Q not in seen:
            R.append(Q)
            seen.add(Q)
            seen.add(-Q)
        Q = Q + K

    v = F(0)
    w = F(0)
    for Q in R:
        xQ, yQ = Q.xy()
        gx = 3 * xQ**2 + a4
        gy = -2 * yQ
        # yQ == 0  <=>  Q is 2-torsion  <=>  Q has no distinct partner -Q
        vQ = gx if yQ == 0 else 2 * gx
        uQ = gy**2
        v += vQ
        w += uQ + xQ * vQ

    return EllipticCurve(E.base_field(), [a4 - 5 * v, a6 - 7 * w])


# ---------------------------------------------------------------------------
# Challenge 1 -- Two Isogenies:  K = (i, 0), a point of order 2
# ---------------------------------------------------------------------------

print("=" * 72)
print("Two Isogenies :  kernel <K>, K = (i, 0)")
print("=" * 72)

K2 = E(i, 0)
assert K2.order() == 2, f"expected order 2, got {K2.order()}"

E2 = velu_codomain(E, K2)
j2 = E2.j_invariant()

print(f"  domain    E  : {E}")
print(f"  codomain  E' : {E2}")
print(f"  j(E')        = {j2}")

# cross-check against Sage's own Velu implementation
phi2 = E.isogeny(K2)
assert phi2.degree() == 2
assert phi2.codomain().j_invariant() == j2, "mismatch vs EllipticCurveIsogeny"
print("  [ok] matches EllipticCurveIsogeny")


# ---------------------------------------------------------------------------
# Challenge 2 -- Three Isogenies:  K = (483728976, 174842350631), order 3
# ---------------------------------------------------------------------------

print()
print("=" * 72)
print("Three Isogenies :  kernel <K>, K = (483728976, 174842350631)")
print("=" * 72)

K3 = E(483728976, 174842350631)
assert K3.order() == 3, f"expected order 3, got {K3.order()}"
# the kernel really is {O, K, [2]K} and [2]K = -K
assert 2 * K3 == -K3

E3 = velu_codomain(E, K3)
j3 = E3.j_invariant()

print(f"  domain    E  : {E}")
print(f"  K            = {K3.xy()}")
print(f"  [2]K         = {(2*K3).xy()}")
print(f"  codomain  E' : {E3}")
print(f"  j(E')        = {j3}")

phi3 = E.isogeny(K3)
assert phi3.degree() == 3
assert phi3.codomain().j_invariant() == j3, "mismatch vs EllipticCurveIsogeny"
print("  [ok] matches EllipticCurveIsogeny")

print()
print(f"FLAG (j-invariant of the 3-isogeny codomain) = {j3}")
