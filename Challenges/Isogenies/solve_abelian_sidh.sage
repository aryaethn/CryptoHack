#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Abelian SIDH" (90)

"I found a way to do SIDH without sending torsion points!"

They did.  It is also completely insecure, and for a reason that has nothing to
do with isogenies being hard or easy.

The scheme
----------
p = 2^216 * 3^137 * q - 1 with q a 256-bit prime, E : y^2 = x^3 + x over F_{p^2},
and G a public point of order q (obtained by clearing the 2- and 3-power parts).

    gen_pubkey(G, l^e):
        R       = P + [r]Q        for a random r, with P,Q a basis of E[l^e]
        phi     = isogeny with kernel <R>,  deg phi = l^e
        phi_hat = dual(phi)
        return (phi, phi_hat),  phi_hat(phi(G))

    derive_secret((phi, phi_hat), H) = phi_hat(phi(H))

Alice uses l^e = 2^216, Bob uses 3^137.  No torsion point images are sent --
which is exactly what the description brags about, and exactly what makes SIDH
resistant to nothing here, because the construction never needed them.

Why it collapses
----------------
The defining property of the dual isogeny is

    phi_hat o phi = [deg phi].

So the "public key" is not a curve or an isogeny evaluation at all:

    G_A = phi_hat_A(phi_A(G)) = [2^216] G,
    G_B = phi_hat_B(phi_B(G)) = [3^137] G,

and the shared secret is

    phi_hat_A(phi_A(G_B)) = [2^216] G_B = [2^216 * 3^137] G.

The random scalar r never appears.  Every degree-2^216 isogeny out of E composes
with its dual to the *same* endomorphism [2^216], so which one Alice picked is
irrelevant -- her private key has no effect on any value anybody sees.  What is
left is a Diffie-Hellman whose "exponents" 2^216 and 3^137 are public
parameters.  Anyone can compute the shared secret from G alone.

The only wrinkle: automorphisms
-------------------------------
source.sage's dual() builds phi_hat as "the isogeny with kernel phi(E[l^e]),
post-composed with an isomorphism back to E".  Isogenies with equal kernels
agree only up to an isomorphism of the codomain, so what it actually returns is

    u o phi_hat   for some u in Aut(E).

E : y^2 = x^3 + x has j = 1728, so Aut(E) = {+-1, +-iota} has order 4 (iota(x,y)
= (-x, i y), and p = 3 mod 4 puts i in F_{p^2}).  Hence

    G_A = u_A [2^216] G,   G_B = u_B [3^137] G,   ss = u_A u_B [2^216 3^137] G.

Aut(E) is abelian, which is why the two parties still agree -- the assert in
source.sage passes.  For us it means the secret is

    ss = u * ( [3^137] G_A )   for one of only four u,

so we compute [3^137] G_A and try all four automorphisms.  Four candidates, and
AES padding tells us which.  Note the same four points arise as u * ([2^216] G_B),
which the script checks as a consistency test.

Aside on the name: "Abelian SIDH" is apt in a way not intended.  Reducing the
group action to plain scalar multiplication does make the whole thing
commutative -- and utterly trivial.
"""

import re
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

# ---------------------------------------------------------------------------
# Parameters (verbatim from source.sage)
# ---------------------------------------------------------------------------

q = 66755491218549620204451278063200785887258235588279474221852899550437797658031
l_a, l_b = 2, 3
e_a, e_b = 216, 137
p = (l_a**e_a) * (l_b**e_b) * q - 1
assert is_pseudoprime(p) and is_pseudoprime(q)

F2 = GF(p**2, name="i", modulus=[1, 0, 1])
i = F2.gen()

E = EllipticCurve(F2, [1, 0])
E.set_order(((l_a**e_a) * (l_b**e_b) * q)**2)


# ---------------------------------------------------------------------------
# Parse output.txt
# ---------------------------------------------------------------------------

text = Path("output_abelian_sidh.txt").read_text()

TERM = re.compile(r"(\d+)\*i \+ (\d+)")


def parse_point(name):
    line = re.search(rf"^{re.escape(name)} = \((.*)\)$", text, re.MULTILINE).group(1)
    coords = TERM.findall(line)
    assert len(coords) == 2, f"expected two coordinates for {name}, got {len(coords)}"
    (ax, bx), (ay, by) = coords
    return E(ZZ(ax) * i + ZZ(bx), ZZ(ay) * i + ZZ(by))


G = parse_point("G")
G_A = parse_point("G_A")
G_B = parse_point("G_B")

iv_hex = re.search(r"iv = ([0-9a-f]+)", text).group(1)
ct_hex = re.search(r"ct = ([0-9a-f]+)", text).group(1)

assert G.order() == q, "G should have order exactly q"
print(f"[ok] G has order q ({q.nbits()} bits)")


# ---------------------------------------------------------------------------
# The public keys are just scalar multiples of G
# ---------------------------------------------------------------------------

auts = E.automorphisms()
print(f"|Aut(E)| = {len(auts)}   (j = {E.j_invariant()})")

cand_A = [u((l_b**e_b) * G_A) for u in auts]            # u * [3^137] G_A
cand_B = [u((l_a**e_a) * G_B) for u in auts]            # u * [2^216] G_B

assert set(cand_A) == set(cand_B), \
    "the two derivations disagree -- the public keys are not [l^e]G up to Aut"
print("[ok] u*[3^137]G_A and u*[2^216]G_B give the same four candidates")

# and confirm G_A, G_B really are scalar multiples of G up to an automorphism
assert any(G_A == u((l_a**e_a) * G) for u in auts), "G_A is not u*[2^216]G"
assert any(G_B == u((l_b**e_b) * G) for u in auts), "G_B is not u*[3^137]G"
print("[ok] G_A = u*[2^216]G and G_B = u*[3^137]G : the private keys are irrelevant")


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

flag = None
for k, ss in enumerate(cand_A):
    key = SHA256.new(data=str(ss).encode()).digest()[:128]
    pt = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex)).decrypt(bytes.fromhex(ct_hex))
    try:
        pt = unpad(pt, 16)
    except ValueError:
        continue
    if pt.startswith(b"crypto{"):
        print(f"\n[+] candidate {k} decrypts")
        print(f"    shared secret = {ss}")
        flag = pt
        break

assert flag is not None, "none of the four candidates decrypted"
print()
print(f"FLAG = {flag.decode()}")
