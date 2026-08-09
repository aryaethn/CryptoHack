#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Prime Power Isogenies" (50)

E0 : y^2 = x^3 + x over F_419,  p + 1 = 2^2 * 3 * 5 * 7.
How many 7-isogenies must you take to get back to E0?

Why the walk is deterministic
-----------------------------
As established in Special Isogenies, E(F_p) = Z/(p+1) is cyclic, so there is a
unique subgroup of order l defined over F_p and therefore a unique F_p-rational
l-isogeny out of every curve on the graph.  "Take the 7-isogeny" is an
unambiguous instruction, and iterating it is a deterministic walk.

The graph is a union of cycles, so the walk must return to its starting point.
In class-group language: the F_p-rational l-isogeny is the action of a fixed
ideal class [l] on the set of supersingular curves over F_p, and the number of
steps to return is the *order of [l] in the class group* of Z[sqrt(-p)].  That
is exactly the number this challenge asks for.

This also shows why CSIDH computes l^e isogenies differently from SIDH.  In
SIDH you find a single point of order l^e and chain down from it.  Here you
cannot: E(F_p) is cyclic of order p+1, and l^e generally does not divide p+1,
so no F_p-rational point of order l^e exists.  Instead you take one l-isogeny,
land on a new curve, find a *fresh* point of order l there, and repeat.  Each
step needs its own point -- that is the loop below.

Bookkeeping note
----------------
Curves are labelled by their Montgomery coefficient A in M_A : y^2 = x^3 + Ax^2 + x,
not by the j-invariant.  The j-invariant is the wrong label here: it cannot
distinguish a curve from its quadratic twist, and twists are genuinely
different vertices of the CSIDH graph (they are what walking the *other*
direction reaches).  Since p = 3 mod 4, each supersingular curve here has a
unique such A, which the assertion below checks at every step.
"""

p = 419
F = GF(p)
ell = 7

E0 = EllipticCurve(F, [0, 0, 0, 1, 0])          # M_0 : y^2 = x^3 + x
assert p % 4 == 3
assert E0.is_supersingular() and E0.order() == p + 1
assert (p + 1) % ell == 0
print(f"p = {p},  p + 1 = {factor(p + 1)},  walking {ell}-isogenies\n")


def montgomery_A(E):
    """The unique A with M_A isomorphic to E over F_p."""
    As = [A for A in F
          if A**2 != 4 and EllipticCurve(F, [0, A, 0, 1, 0]).is_isomorphic(E)]
    assert len(As) == 1, f"expected a unique Montgomery coefficient, got {As}"
    return As[0]


def step(A):
    """Apply the unique F_p-rational l-isogeny to M_A and return the new A."""
    E = EllipticCurve(F, [0, A, 0, 1, 0])
    assert E.abelian_group().invariants() == (p + 1,), "E(F_p) is not cyclic"

    cofactor = (p + 1) // ell
    P = None
    while P is None:
        R = cofactor * E.random_point()
        if R.order() == ell:
            P = R

    phi = E.isogeny(P)
    assert phi.degree() == ell
    return montgomery_A(phi.codomain())


# ---------------------------------------------------------------------------
# Walk the cycle
# ---------------------------------------------------------------------------

A = F(0)
path = [A]
for n in range(1, 1000):
    A = step(A)
    path.append(A)
    print(f"  step {n:2d}:  A = {A}")
    if A == 0:
        break
else:
    raise RuntimeError("did not return to E0")

print(f"\ncycle: {' -> '.join(str(a) for a in path)}")
print(f"all curves on the cycle are distinct: {len(set(path[:-1])) == len(path[:-1])}")

# The walk is deterministic, so re-running it must retrace the same cycle.
again = [F(0)]
while True:
    again.append(step(again[-1]))
    if again[-1] == 0:
        break
assert again == path, "the walk was not deterministic"
print("[ok] independent re-run produced the identical cycle")

print()
print(f"FLAG (number of {ell}-isogenies to return to E0) = {n}")
