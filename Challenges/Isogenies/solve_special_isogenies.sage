#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Special Isogenies" (30)

E0 : y^2 = x^3 + x over F_419.  Compute a degree-5 isogeny and report the
Montgomery coefficient A of the codomain.

The point of the challenge
--------------------------
SIDH lives on supersingular curves over F_{p^2}; CSIDH restricts to curves
defined over F_p.  That restriction changes the shape of the isogeny graph
completely, and the reason is a statement about group structure:

    E(F_p) = Z/(p+1)   -- cyclic.

A cyclic group has *exactly one* subgroup of each order dividing its own.  So
for each prime l | p+1 there is a unique subgroup of order l defined over F_p,
hence a unique l-isogeny defined over F_p.  There is no choice of kernel to
make: "the" 5-isogeny is well defined.

Contrast with SIDH, where E[l] = Z/l x Z/l gives l+1 distinct order-l
subgroups and therefore l+1 different l-isogenies -- the branching that makes
the supersingular graph an expander, and that Alice and Bob's secrets walk
through.  Over F_p the graph collapses to unions of cycles ("isogeny
volcanoes" at the crater level), which is exactly the structure the CSIDH class
group action needs.

That is what the challenge means by "compute another point of order 5 and
repeat -- what do you see?"  You get the same curve, every time, because every
point of order 5 generates the same subgroup.  This script verifies that
rather than asserting it.

Here p = 419, p + 1 = 420 = 2^2 * 3 * 5 * 7, so a 5-isogeny exists over F_p.

Montgomery form
---------------
CSIDH represents curves as  M_A : y^2 = x^3 + A x^2 + x,  and the coefficient A
is the whole public key -- one field element.  Sending x -> x - A/3 clears the
x^2 term and gives the short Weierstrass model Velu works in:

    y^2 = x^3 + (1 - A^2/3) x + (2A^3/27 - A/3)

so to report A we invert that, by testing which M_A is F_p-isomorphic to the
Velu codomain.  Over F_419 that search is trivial, and doing it exhaustively
also shows how many A's are admissible, which is worth seeing: M_A and M_{-A}
are quadratic twists, and are *not* isomorphic over F_p here because the
twisting map (x,y) -> (-x, iy) needs i = sqrt(-1), which does not exist in
F_419 (419 = 3 mod 4).
"""

p = 419
F = GF(p)

E0 = EllipticCurve(F, [0, 0, 0, 1, 0])          # y^2 = x^3 + x, i.e. M_0

assert p % 4 == 3
assert E0.is_supersingular()
assert E0.order() == p + 1 == 420
assert factor(p + 1) == factor(420)

# E(F_p) is cyclic -- this is the fact the whole challenge rests on
assert E0.abelian_group().invariants() == (420,), "E(F_p) is not cyclic!"
print(f"E0(F_{p}) = Z/{E0.order()}   (cyclic)   #E = {factor(E0.order())}")


def montgomery_coefficient(E):
    """All A in F_p with  M_A : y^2 = x^3 + A x^2 + x  isomorphic to E over F_p."""
    out = []
    for A in F:
        if A**2 == 4:                # singular: x^3 + Ax^2 + x has a double root
            continue
        if EllipticCurve(F, [0, A, 0, 1, 0]).is_isomorphic(E):
            out.append(A)
    return out


# ---------------------------------------------------------------------------
# Every point of order 5 gives the same isogeny
# ---------------------------------------------------------------------------

cofactor = (p + 1) // 5
codomains = []
generators = set()

for _ in range(200):
    P = cofactor * E0.random_point()
    if P.order() != 5:
        continue
    generators.add(frozenset(tuple(R.xy()) if R else None for R in [k * P for k in range(5)]))
    phi = E0.isogeny(P)
    assert phi.degree() == 5
    codomains.append(phi.codomain())

print(f"\nsampled {len(codomains)} points of order 5")
print(f"distinct order-5 subgroups found: {len(generators)}   (cyclic group => must be 1)")
assert len(generators) == 1, "more than one order-5 subgroup -- group is not cyclic"

js = {E.j_invariant() for E in codomains}
assert len(js) == 1, "different points of order 5 gave different codomains"
print(f"distinct codomain j-invariants: {len(js)}  ->  j = {js.pop()}")

Ecod = codomains[0]
print(f"Velu codomain (short Weierstrass): {Ecod}")

As = montgomery_coefficient(Ecod)
print(f"\nMontgomery coefficients A with M_A isomorphic to the codomain over F_{p}: {As}")

# sanity: the domain itself is M_0
assert 0 in montgomery_coefficient(E0)

A = As[0]
print()
print(f"FLAG (Montgomery coefficient A) = {A}")
