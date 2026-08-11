#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Meet me in the Claw" (120)

"Alice forgot to send me her torsion data! How am I going to compute the
shared secret??"

p = 2^35 * 3^29 - 1,  E0 : y^2 = x^3 + x over F_{p^2}.  We are given the public
bases (P2,Q2), (P3,Q3), Alice's curve EA, and -- unusually -- *Bob's secret*
sB = 495832856.  Alice's torsion images phiA(P3), phiA(Q3) are missing.

Why the usual attacks do not apply
----------------------------------
Every previous break in this category fed on published torsion data:
What's My Kernel and Dual Masters both got the secret straight out of image
points, and Breaking SIDH needed phiB(P2), phiB(Q2) to build the Kani kernel.
Here there is *no* torsion data at all.  What is left is the bare isogeny
problem -- given E0 and EA, both supersingular, find the 2^35-isogeny between
them -- and that problem is not known to be broken.  The best classical
algorithm is generic: meet in the middle, a.k.a. claw finding.

The claw
--------
Alice's isogeny factors as phi_A = phi_2 o phi_1 with

    phi_1 : E0    -> E_mid   of degree 2^18,
    phi_2 : E_mid -> EA      of degree 2^17.

Grow both sides and look for a collision in j-invariants:

  * Left.  ker phi_A = <P2 + [sA]Q2>, so ker phi_1 = <[2^17](P2 + [sA]Q2)>
    = <A + [s0]B> with A = [2^17]P2, B = [2^17]Q2 of order 2^18 and
    s0 = sA mod 2^18.  That is 2^18 = 262144 candidate curves.
  * Right.  We know nothing about phi_2's kernel, so enumerate *all* cyclic
    subgroups of order 2^17 in EA[2^17].  There are 3*2^16 = 196608 of them:
    <R1 + [t]R2> for t in [0,2^17), plus <R2 + [2u]R1> for u in [0,2^16).

A collision pins down E_mid and hands over s0 = sA mod 2^18.  The remaining 17
bits come from a second, cheap sweep: with sA = s0 + 2^18*s1,

    ker phi_2 = < phi_1(P2 + [s0]Q2) + [s1] * [2^18] phi_1(Q2) >,

so run the same tree from E_mid over s1 in [0,2^17) and keep the leaf whose
j-invariant is j(EA).

Total work ~ 2^18 + 2^17.6, i.e. O(sqrt(2^35)) = O(p^{1/4}) -- the classical
security level of SIDH, and the reason SIDH's 2-torsion exponent had to be
about twice the target security parameter.  (Quantumly this is Tani's claw
algorithm at O(p^{1/6}); and of course since 2022 the torsion-point attacks
demolish real SIDH far faster than either.  None of that applies here, because
no torsion data was published -- which is exactly what makes this challenge a
*generic* search rather than an algebraic break.)

Growing a tree instead of recomputing isogenies
-----------------------------------------------
Computing 2^18 separate degree-2^18 isogenies would be ~4.7M two-isogeny steps.
Growing a binary tree instead costs one step per *node*, ~2^19 total, because
depth-d nodes share their first d steps.  The key fact making the tree
well-defined: the first d steps of the chain for <G + [t]H> are determined by
<[2^(k-d)](G + [t]H)>, which depends only on t mod 2^d.

State carried down the tree is (a4, a6, Gd, Kd) where Gd = phi_d(G + [t0]H) and
Kd = [2^d] phi_d(H); then the next kernel is [2^(k-1-d)]Gd for the left child
and that plus [2^(k-1-d)]Kd for the right, and Kd doubles at each level.  When
[2^(k-1-d)]Kd vanishes the node has a single child -- which is exactly what
makes the second right-hand family (where H has order 2^16, not 2^17) a
2^16-leaf tree rather than 2^17.

All curve arithmetic is done on raw (x,y) tuples with explicit Velu formulas
rather than Sage EllipticCurve objects; the object overhead is ~100x here and
the tree has half a million nodes.  The primitives are checked against Sage
before use.
"""

import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

# ---------------------------------------------------------------------------
# Parameters (verbatim from source.sage)
# ---------------------------------------------------------------------------

ea, eb = 35, 29
p = 2**ea * 3**eb - 1
F = GF(p**2, name="i", modulus=[1, 0, 1])
i = F.gen()

E0 = EllipticCurve(F, [1, 0])
P2 = E0(1956194174015565770794336*i + 1761758151759977040301838, 2069089015584979134622338*i + 203179590296749797202321)
Q2 = E0(2307879706216488835068177*i + 525239361975369850140518, 1834477572646982833868802*i + 733730165545948547648966)
P3 = E0(2162781291023757368295120*i + 1542032609308508307064948, 1130418491160933565948899*i + 904285233345649302734471)
Q3 = E0(365294178628988623980343*i + 1867216057142335172490873, 2141125983272329025279178*i + 1860108401614981479394873)

EAa = 2336060373130772918448023*i + 63223462935813026254900
EAb = 202739861418983960259548*i + 525917254309082638166498
EA = EllipticCurve(F, [EAa, EAb])

sB = 495832856

iv_hex = '9a030e6824e7ec5d66b3443920ea76cb'
ct_hex = '7f11a2ca0359cc5f3a81d5039643b1208ac7eb17f8bd42600d1f67e474cd664dcb8624c94175e167acfe856f48be34bd'

assert P2.order() == Q2.order() == 2**ea
assert P3.order() == Q3.order() == 3**eb

A_HALF, B_HALF = 18, 17                      # 18 + 17 = 35


# ---------------------------------------------------------------------------
# Fast raw-coordinate arithmetic  (None = point at infinity)
# ---------------------------------------------------------------------------

def dbl(a4, P):
    if P is None:
        return None
    x, y = P
    if y == 0:
        return None
    lam = (3*x*x + a4) / (2*y)
    x3 = lam*lam - 2*x
    return (x3, lam*(x - x3) - y)


def add(a4, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        return dbl(a4, P) if y1 == y2 else None
    lam = (y2 - y1) / (x2 - x1)
    x3 = lam*lam - x1 - x2
    return (x3, lam*(x1 - x3) - y1)


def mul(a4, k, P):
    R, Q = None, P
    while k:
        if k & 1:
            R = add(a4, R, Q)
        Q = dbl(a4, Q)
        k >>= 1
    return R


def two_iso(a4, a6, T):
    """Velu for a kernel <T> of order 2, T = (xT, 0).  u_T = 0, v_T = g^x_T."""
    xT = T[0]
    v = 3*xT*xT + a4
    return a4 - 5*v, a6 - 7*(xT*v), (xT, v)


def push(par, P):
    """Evaluate the 2-isogeny; Y = y * dX/dx since Velu is normalised."""
    if P is None:
        return None
    xT, v = par
    x, y = P
    d = x - xT
    if d == 0:
        return None                            # P lies in the kernel
    inv = 1 / d
    return (x + v*inv, y*(1 - v*inv*inv))


def jinv(a4, a6):
    n = 4*a4**3
    return 1728 * n / (n + 27*a6**2)


def tup(P):
    return (P.xy()[0], P.xy()[1])


# --- self-check against Sage before trusting any of it ----------------------
for s0 in (0, 1, 12345):
    G = (2**17)*P2 + s0*((2**17)*Q2)
    ref = E0.isogeny(G, algorithm="factored").codomain().j_invariant()
    a4, a6, Gt = F(1), F(0), tup(G)
    for d in range(18):
        a4, a6, par = two_iso(a4, a6, mul(a4, 1 << (17 - d), Gt))
        Gt = push(par, Gt)
    assert jinv(a4, a6) == ref, "raw arithmetic disagrees with Sage"
print("[ok] raw 2-isogeny arithmetic validated against Sage\n")


# ---------------------------------------------------------------------------
# The tree: enumerate isogenies with kernel <G + [t]H>
# ---------------------------------------------------------------------------

def walk(a4, a6, G, H, k, leaf):
    """
    Depth-k binary tree over kernels <G + [t]H>.  Calls leaf(t, a4, a6, Gd)
    at every leaf.  A node has one child instead of two when the branching
    point [2^(k-1-d)]Kd vanishes.
    """
    stack = [(0, a4, a6, G, H, 0)]
    while stack:
        d, A4, A6, Gd, Kd, t0 = stack.pop()
        if d == k:
            leaf(t0, A4, A6, Gd)
            continue
        e = 1 << (k - 1 - d)
        W = mul(A4, e, Gd)
        Z = mul(A4, e, Kd)
        Kd2 = dbl(A4, Kd)
        for c in ((0, 1) if Z is not None else (0,)):
            Gc = Gd if c == 0 else add(A4, Gd, Kd)
            T = W if c == 0 else add(A4, W, Z)
            a4n, a6n, par = two_iso(A4, A6, T)
            stack.append((d + 1, a4n, a6n, push(par, Gc), push(par, Kd2),
                          t0 + (c << d)))


# ---------------------------------------------------------------------------
# Left half: 2^18 curves from E0
# ---------------------------------------------------------------------------

A = (2**B_HALF) * P2
B = (2**B_HALF) * Q2
assert A.order() == B.order() == 2**A_HALF

print(f"[*] growing the left tree: 2^{A_HALF} curves from E0 ...")
t0 = time.time()
left = {}


def left_leaf(t, a4, a6, _G):
    left[jinv(a4, a6)] = t


walk(F(1), F(0), tup(A), tup(B), A_HALF, left_leaf)
print(f"    {len(left)} distinct j-invariants in {time.time() - t0:.0f}s")


# ---------------------------------------------------------------------------
# Right half: all 3*2^16 cyclic 2^17-subgroups of EA
# ---------------------------------------------------------------------------

cof = (p + 1) // 2**B_HALF
R1 = R2 = None
while True:
    R1 = cof * EA.random_point()
    R2 = cof * EA.random_point()
    if R1.order() == R2.order() == 2**B_HALF and \
       R1.weil_pairing(R2, 2**B_HALF).multiplicative_order() == 2**B_HALF:
        break

print(f"[*] growing the right tree: 3*2^{B_HALF - 1} curves from EA ...")
t0 = time.time()
hits = []


def right_leaf(t, a4, a6, _G):
    j = jinv(a4, a6)
    if j in left:
        hits.append((left[j], j))


walk(EAa, EAb, tup(R1), tup(R2), B_HALF, right_leaf)          # <R1 + [t]R2>
walk(EAa, EAb, tup(R2), tup(2*R1), B_HALF, right_leaf)        # <R2 + [2u]R1>
print(f"    done in {time.time() - t0:.0f}s;  {len(hits)} collision(s)")

assert hits, "no claw found"
s0 = hits[0][0]
j_mid = hits[0][1]
print(f"[+] claw found:  sA mod 2^{A_HALF} = {s0}\n")


# ---------------------------------------------------------------------------
# Second sweep: the remaining 17 bits
# ---------------------------------------------------------------------------

phi1 = E0.isogeny(A + s0*B, algorithm="factored")
E_mid = phi1.codomain()
assert E_mid.j_invariant() == j_mid

A2 = phi1(P2 + s0*Q2)
B2 = (2**A_HALF) * phi1(Q2)
assert A2.order() == B2.order() == 2**B_HALF

print(f"[*] sweeping the remaining {B_HALF} bits from E_mid ...")
t0 = time.time()
jA = EA.j_invariant()
found = []


def s1_leaf(t, a4, a6, _G):
    if jinv(a4, a6) == jA:
        found.append(t)


walk(E_mid.a4(), E_mid.a6(), tup(A2), tup(B2), B_HALF, s1_leaf)
print(f"    done in {time.time() - t0:.0f}s;  {len(found)} candidate(s)")
assert found, "second sweep failed"


# ---------------------------------------------------------------------------
# Recover sA, complete Bob's side of the exchange, decrypt
# ---------------------------------------------------------------------------

flag = None
for s1 in found:
    sA = s0 + (1 << A_HALF) * s1
    KA = P2 + sA * Q2
    if KA.order() != 2**ea:
        continue
    phiA = E0.isogeny(KA, algorithm="factored")
    if phiA.codomain().j_invariant() != jA:
        continue

    print(f"\n[+] RECOVERED Alice's secret:  sA = {sA}")
    print("    verified: E0/<P2 + [sA]Q2> has the same j-invariant as EA")

    # the torsion data Alice "forgot" to send, reconstructed
    psi = phiA.codomain().isomorphism_to(EA)
    phiA_P3 = psi(phiA(P3))
    phiA_Q3 = psi(phiA(Q3))

    KS = phiA_P3 + sB * phiA_Q3
    assert KS.order() == 3**eb
    shared = EA.isogeny(KS, algorithm="factored").codomain().j_invariant()

    key = SHA256.new(data=str(shared).encode()).digest()[:128]
    pt = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex)).decrypt(bytes.fromhex(ct_hex))
    try:
        pt = unpad(pt, 16)
    except ValueError:
        continue
    if pt.startswith(b"crypto{"):
        print(f"    shared secret j = {shared}")
        flag = pt
        break

assert flag is not None, "no candidate decrypted"
print()
print(f"FLAG = {flag.decode()}")
