#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Secret Exponents" (60)

E0 : y^2 = x^3 + x over F_419,  p + 1 = 2^2 * 3 * 5 * 7.
Secret exponent vector [2, 3, 4] against the odd primes [3, 5, 7].
Report the Montgomery coefficient A of the codomain.

What a CSIDH private key is
---------------------------
A CSIDH private key is not a scalar, it is an exponent vector

    (e_0, ..., e_k)  against the odd primes  l_0, ..., l_k  dividing p+1,

and it denotes the ideal class

    [l_0]^{e_0} * ... * [l_k]^{e_k}   acting on the starting curve.

Concretely: take e_0 isogenies of degree l_0, then e_1 of degree l_1, and so
on.  Here that is 2 three-isogenies, 3 five-isogenies and 4 seven-isogenies, a
composite isogeny of degree 3^2 * 5^3 * 7^4.

The single property that makes this a key exchange is **commutativity**: the
class group is abelian, so applying the steps in any order lands on the same
curve, and Alice's vector followed by Bob's equals Bob's followed by Alice's.
That is precisely what SIDH lacked -- SIDH had to ship torsion-point images to
force the square to commute, and that patch is what got it killed.  CSIDH needs
no such crutch, which is why the 2022 break does not touch it.

The script verifies commutativity directly by evaluating the vector in several
random orders and checking the answers agree.

An independent check via the class group
----------------------------------------
From Prime Power Isogenies we know [l_7] has order 27 = h, so it *generates*
the whole class group.  Every other class is therefore a power of it:

    [l_3] = [l_7]^{k3},     [l_5] = [l_7]^{k5}

and the whole secret vector collapses to a single exponent

    2*k3 + 3*k5 + 4  (mod 27)

whose curve we can read straight off the 7-isogeny cycle.  Computing the
answer that way uses completely different arithmetic from walking the isogenies
directly, so agreement between the two is a real check rather than a
restatement.
"""

p = 419
F = GF(p)
primes = [3, 5, 7]
secret = [2, 3, 4]

E0 = EllipticCurve(F, [0, 0, 0, 1, 0])          # M_0
assert p % 4 == 3 and E0.is_supersingular() and E0.order() == p + 1
for l in primes:
    assert (p + 1) % l == 0
print(f"p = {p},  p + 1 = {factor(p + 1)}")
print(f"primes {primes}, secret vector {secret}")
print(f"isogeny degree = {' * '.join(f'{l}^{e}' for l, e in zip(primes, secret))}"
      f" = {prod(l**e for l, e in zip(primes, secret))}\n")


def montgomery_A(E):
    """The unique A with M_A isomorphic to E over F_p."""
    As = [A for A in F
          if A**2 != 4 and EllipticCurve(F, [0, A, 0, 1, 0]).is_isomorphic(E)]
    assert len(As) == 1, f"expected a unique Montgomery coefficient, got {As}"
    return As[0]


def step(A, ell):
    """Apply the unique F_p-rational ell-isogeny to M_A; return the new A."""
    E = EllipticCurve(F, [0, A, 0, 1, 0])
    cofactor = (p + 1) // ell
    while True:
        R = cofactor * E.random_point()
        if R.order() == ell:
            break
    phi = E.isogeny(R)
    assert phi.degree() == ell
    return montgomery_A(phi.codomain())


def group_action(A, primes, exponents):
    """Apply [l_0]^e_0 ... [l_k]^e_k to M_A, one prime-degree step at a time."""
    for l, e in zip(primes, exponents):
        assert e >= 0, "negative exponents need the twist trick (a later challenge)"
        for _ in range(e):
            A = step(A, l)
    return A


# ---------------------------------------------------------------------------
# Direct evaluation
# ---------------------------------------------------------------------------

A_final = group_action(F(0), primes, secret)
print(f"direct evaluation:  A = {A_final}")


# ---------------------------------------------------------------------------
# Commutativity: the order of the steps must not matter
# ---------------------------------------------------------------------------

steps = [l for l, e in zip(primes, secret) for _ in range(e)]
for trial in range(5):
    order = list(steps)
    shuffle(order)
    A = F(0)
    for l in order:
        A = step(A, l)
    assert A == A_final, f"order {order} gave {A}, not {A_final}"
print(f"[ok] 5 random orderings of the {len(steps)} steps all give the same curve")


# ---------------------------------------------------------------------------
# Independent check through the class group
# ---------------------------------------------------------------------------

# the full 7-isogeny cycle: cycle[k] = A of [l_7]^k * E0
cycle = [F(0)]
while True:
    cycle.append(step(cycle[-1], 7))
    if cycle[-1] == 0:
        cycle.pop()
        break
h = len(cycle)
print(f"\n[l_7] has order {h} and generates the class group (h = {h})")

k3 = cycle.index(step(F(0), 3))
k5 = cycle.index(step(F(0), 5))
print(f"  [l_3] = [l_7]^{k3}")
print(f"  [l_5] = [l_7]^{k5}")

k = (secret[0] * k3 + secret[1] * k5 + secret[2] * 1) % h
print(f"  2*{k3} + 3*{k5} + 4*1 = {k} (mod {h})")
print(f"  cycle[{k}] = {cycle[k]}")
assert cycle[k] == A_final, "class-group prediction disagrees with the direct walk"
print("[ok] class-group prediction matches the direct computation")

print()
print(f"FLAG (Montgomery coefficient A) = {A_final}")
