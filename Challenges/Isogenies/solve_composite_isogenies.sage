#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Composite Isogenies" (60)

Goal
----
E : y^2 = x^3 + x over F_{p^2},  p = 2^18 * 3^13 - 1,
K = (357834818388*i + 53943911829, 46334220304*i + 267017462655)  of order 3^13.

Compute the 3^13-isogeny phi : E -> E' with ker(phi) = <K> and report j(E').

Why not apply Velu directly
---------------------------
Velu's formulas sum over one representative of each pair {Q, -Q} in the kernel.
For a kernel of order 3^13 = 1594323 that is ~800k field inversions and, worse,
requires materialising the whole subgroup.  The cost is linear in the *degree*,
which is exponential in the input size.  Unusable.

The chaining trick
------------------
An isogeny of degree n = p0^e0 * p1^e1 * ... factors as a composition of
prime-degree steps.  For n = l^e with kernel <K>, ord(K) = l^e:

    E_0 = E,  K_0 = K
    for j = 0 .. e-1:
        T_j     = [l^(e-1-j)] K_j        # has order exactly l
        phi_j   : E_j -> E_j / <T_j> = E_{j+1}      (a degree-l Velu step)
        K_{j+1} = phi_j(K_j)             # order drops by a factor of l

    phi = phi_{e-1} o ... o phi_1 o phi_0

Correctness.  ord(K_j) = l^(e-j) by induction: phi_j kills exactly the subgroup
<T_j> of order l inside <K_j>, so the image of K_j has order l^(e-j)/l.  Each
T_j is a point of order l, so each phi_j has degree l, and deg(phi) = l^e as
required.  ker(phi) contains K and has order l^e = ord(K), hence equals <K>.

Cost: e Velu steps of O(l) each, i.e. O(e*l) instead of O(l^e).  Here 13 steps
of cost 1 instead of ~800000.  This "scale down, push through, repeat" loop is
precisely the inner loop of SIDH key generation.

Velu's formulas, with point evaluation
--------------------------------------
For E : y^2 = x^3 + a4 x + a6 and kernel subgroup G, let R hold the 2-torsion of
G together with one representative of each pair {Q,-Q}.  For Q = (xQ,yQ) in R:

    gx_Q = 3 xQ^2 + a4,   gy_Q = -2 yQ,   u_Q = gy_Q^2 = 4 yQ^2,
    v_Q  = gx_Q  if yQ = 0  else  2 gx_Q

    v = sum v_Q,   w = sum ( u_Q + xQ v_Q )
    E' : Y^2 = X^3 + (a4 - 5v) X + (a6 - 7w)

and the map itself is

    X(x)   = x + sum_Q [ v_Q/(x-xQ) + u_Q/(x-xQ)^2 ]
    Y(x,y) = y * dX/dx = y * ( 1 - sum_Q [ v_Q/(x-xQ)^2 + 2 u_Q/(x-xQ)^3 ] )

The identity Y = y * dX/dx is not a coincidence to memorise: Velu's isogeny is
*normalised*, meaning it pulls the invariant differential back to itself,
phi^*(dX/Y) = dx/y.  Substituting X = X(x), Y = y * g(x) into that relation
forces g = dX/dx.  It is also a free correctness check on any implementation.
"""

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

p = 2**18 * 3**13 - 1
assert is_prime(p) and p % 4 == 3

F = GF(p**2, names="i", modulus=[1, 0, 1])
i = F.gen()

E = EllipticCurve(F, [1, 0])          # y^2 = x^3 + x

K = E(357834818388 * i + 53943911829, 46334220304 * i + 267017462655)


# ---------------------------------------------------------------------------
# Velu: codomain + evaluation
# ---------------------------------------------------------------------------

def velu(E, T):
    """
    Velu's formulas for the separable isogeny phi : E -> E/<T>.

    E must be short Weierstrass (a1 = a2 = a3 = 0).
    Returns (Ecod, evaluate) where evaluate(P) is phi(P) as a point of Ecod.
    Points of <T> map to the identity.
    """
    a1, a2, a3, a4, a6 = E.a_invariants()
    assert (a1, a2, a3) == (0, 0, 0), "expected short Weierstrass form"
    Fld = E.base_field()

    # R: one representative per {Q,-Q}, plus any 2-torsion (which is self-paired)
    R, seen = [], set()
    Q = T
    while Q != E(0):
        if Q not in seen:
            R.append(Q)
            seen.add(Q)
            seen.add(-Q)
        Q = Q + T

    data = []                      # (xQ, u_Q, v_Q) per representative
    v_sum = Fld(0)
    w_sum = Fld(0)
    for Q in R:
        xQ, yQ = Q.xy()
        gx = 3 * xQ**2 + a4
        vQ = gx if yQ == 0 else 2 * gx
        uQ = 4 * yQ**2
        data.append((xQ, uQ, vQ))
        v_sum += vQ
        w_sum += uQ + xQ * vQ

    Ecod = EllipticCurve(Fld, [a4 - 5 * v_sum, a6 - 7 * w_sum])

    kernel_x = {xQ for xQ, _, _ in data}

    def evaluate(P):
        if P == E(0):
            return Ecod(0)
        x, y = P.xy()
        if x in kernel_x:          # P lies in the kernel
            return Ecod(0)
        X = x
        dX = Fld(1)
        for xQ, uQ, vQ in data:
            d = x - xQ
            d2 = d * d
            X += vQ / d + uQ / d2
            dX -= vQ / d2 + 2 * uQ / (d2 * d)
        return Ecod(X, y * dX)     # Y = y * dX/dx  (normalised isogeny)

    return Ecod, evaluate


# ---------------------------------------------------------------------------
# Chain of prime-degree steps
# ---------------------------------------------------------------------------

def isogeny_chain(E, K, l, e, verbose=True):
    """Compute the codomain of the degree l^e isogeny with kernel <K>."""
    assert K.order() == l**e, f"expected order {l}^{e}, got {K.order()}"

    Ecur, Kcur = E, K
    for j in range(e):
        T = (l**(e - 1 - j)) * Kcur
        assert T.order() == l

        Ecur, evaluate = velu(Ecur, T)
        if j < e - 1:                     # last step sends K to the identity
            Kcur = evaluate(Kcur)
            assert Kcur.order() == l**(e - 1 - j), "order did not drop by l"

        if verbose:
            print(f"  step {j + 1:2d}/{e}:  deg {l}  ->  j = {Ecur.j_invariant()}")

    return Ecur


print("=" * 74)
print("Composite Isogenies :  3^13-isogeny by chaining 13 three-isogenies")
print("=" * 74)
print(f"  p        = 2^18 * 3^13 - 1 = {p}")
print(f"  E        : {E}")
print(f"  ord(K)   = {factor(K.order())}")
print()

Ecod = isogeny_chain(E, K, l=3, e=13)
j = Ecod.j_invariant()

print()
print(f"  codomain E' : {Ecod}")
print(f"  j(E')       = {j}")


# ---------------------------------------------------------------------------
# Independent cross-check: Sage's own factored-isogeny implementation
# ---------------------------------------------------------------------------

from sage.schemes.elliptic_curves.hom_composite import EllipticCurveHom_composite

phi = EllipticCurveHom_composite(E, K)
assert phi.degree() == 3**13, f"degree is {phi.degree()}, expected 3^13"
assert phi.codomain().j_invariant() == j, "mismatch vs EllipticCurveHom_composite"
assert phi(K) == phi.codomain()(0), "K is not in the kernel"
print("  [ok] degree = 3^13, K in kernel, j matches EllipticCurveHom_composite")

print()
print(f"FLAG (j-invariant of the 3^13-isogeny codomain) = {j}")
