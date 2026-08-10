#!/usr/bin/env sage
"""
CryptoHack :: Isogenies :: "Andre Encoding" (80)

"I've developed a novel encryption protocol, the only thing left is to look
into compression"

The scheme
----------
p = 37 * 2^64 * lcm(1..255) - 1,  E : y^2 = x^3 + 1 over F_{p^2}, supersingular
with #E = (p+1)^2, and P, Q a basis of E[p+1].  For each plaintext byte b:

    s   = random in [0, 2^64 * b]
    ker = [(p+1) / (2^64 * b)] * (P + [s]Q)
    phi = the isogeny with kernel <ker>
    ciphertext entry = ( phi(P), phi(Q) )

Note b <= 255 always divides lcm(1..255), so 2^64*b | p+1 and the construction
is well defined.  The randomness s hides which isogeny was taken; nothing about
s is transmitted.

The leak
--------
In the basis (P, Q) the point P + [s]Q has coordinate vector (1, s), whose order
is (p+1)/gcd(p+1, gcd(1,s)) = p+1 -- *always*, for every s, because the first
coordinate is 1.  So ker has order exactly 2^64 * b and

    deg phi = 2^64 * b,

with no dependence on s whatsoever.  The random scalar changes *which* isogeny
is used but never its degree, and the degree is the plaintext.

Degree is not hidden by publishing images: the Weil pairing turns it into an
exponent.  For any S, T in E[n],

    e_n( phi(S), phi(T) ) = e_n(S, T)^{deg phi}.

So with z = e_n(P, Q) and w = e_n(phi(P), phi(Q)) we get w = z^{2^64 * b}, and
recovering b is a discrete log in a group whose order is 37 * 2^64 * lcm(1..255)
-- about as smooth as an integer gets.  Each byte falls independently.

That is the joke in the description: worrying about "compression" of a 57 KB
ciphertext for a 51-byte flag, while every byte is individually recoverable from
its own ciphertext block in microseconds.  It is a per-byte ECB-shaped design,
where the "codebook" is indexed by isogeny degree.

Making it cheap
---------------
A pairing on the full (p+1)-torsion means a 432-bit Miller loop.  Unnecessary:
we only need b in [1,255].  Pick m = 239*241 = 57599, an odd divisor of p+1 that
exceeds 255, and pair on the m-torsion instead.  Scaling commutes with phi,

    [(p+1)/m] phi(P) = phi( [(p+1)/m] P ),

so with P' = [(p+1)/m]P and Q' = [(p+1)/m]Q we get
e_m(phi(P)', phi(Q)') = e_m(P', Q')^{2^64 b}.  The Miller loop drops to 16 bits.
Since m is odd, 2^64 is invertible mod m, and b < 255 < m makes the answer
unique -- so a 255-entry lookup table finishes it with no discrete log at all.

Reconstructing the codomains
----------------------------
The ciphertext gives only the two image points, never the codomain curve.  It
does not need to: a curve y^2 = x^3 + Ax + B through two points with distinct
x-coordinates is pinned down by a 2x2 linear system,

    A = ((y1^2 - x1^3) - (y2^2 - x2^3)) / (x1 - x2),   B = y1^2 - x1^3 - A*x1,

which is itself a small lesson about how little "just send the points" hides.
"""

import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Parameters (verbatim from source.sage)
# ---------------------------------------------------------------------------

p = 37 * 2**64 * lcm(range(1, 256)) - 1
assert is_prime(p)
n = p + 1

F = GF(p**2, name="i", modulus=[1, 0, 1])
i = F.gen()

E = EllipticCurve(F, [0, 1])
E.set_order(n**2)

P = E(2754452008418475544762931777380298061286322242088097042789979017337032668335152047250270118628626846112409632316814344852346179989*i + 300888031019145372993855450123312195268855753102882163072967372426589237335996165853668912727448513477444811191182550244111536735,
      4048396253042221946332182039831591283289177370092736377609511682595711744157657185583897171948127827836521892887941707373829426385*i + 5574313210012278375687658199880462698154719575075630281638825753946911987283962578905520742770486366773314976292767579688991668535)
Q = E(1914292834750542008365772941838940247194316211832948370075234167086803005671626788818592170824160266813720050022811399854833864570*i + 675917976944321956275103708696442108160242821688340828072457829850507425923003867371226253254729899087222613984510532839645132037,
      1353413969699500553835259943514301405386193613479830974260135363453012387178560466458631824224103775101292443946360403995987929735*i + 2642848780435012471695812611372313188888541702956899224702856112971832879700145426992696527731460150858414996112482220450878252755)

# ---------------------------------------------------------------------------
# Pair on a small odd subgroup instead of the full (p+1)-torsion
# ---------------------------------------------------------------------------

m = 239 * 241                      # odd, divides lcm(1..255), and > 255
assert n % m == 0 and m % 2 == 1 and m > 255
cof = n // m

Pm, Qm = cof * P, cof * Q
assert Pm.order() == Qm.order() == m
z = Pm.weil_pairing(Qm, m)
assert z.multiplicative_order() == m, "P, Q do not form a basis of E[m]"

u = z**(2**64)                     # w will be u^b
table = {}
acc = F(1)
for b in range(1, 256):
    acc *= u
    assert acc not in table, "collision: u^b is not injective on [1,255]"
    table[acc] = b

print(f"p has {p.nbits()} bits;  pairing on the {m}-torsion instead of the full {n.nbits()}-bit group")
print(f"lookup table built for all 255 possible bytes\n")


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

def to_field(coeffs):
    c0, c1 = coeffs
    return F(c0) + F(c1) * i


def codomain_and_points(entry):
    """Rebuild the codomain curve from the two published points."""
    x1, y1 = to_field(entry["P"]["x"]), to_field(entry["P"]["y"])
    x2, y2 = to_field(entry["Q"]["x"]), to_field(entry["Q"]["y"])
    assert x1 != x2, "cannot pin down the curve from these two points"
    A = ((y1**2 - x1**3) - (y2**2 - x2**3)) / (x1 - x2)
    B = y1**2 - x1**3 - A * x1
    Ec = EllipticCurve(F, [A, B])
    Ec.set_order(n**2)
    return Ec, Ec(x1, y1), Ec(x2, y2)


ct = json.loads(Path("output_andre.txt").read_text())
print(f"{len(ct)} ciphertext blocks")

flag = bytearray()
for k, entry in enumerate(ct):
    Ec, phiP, phiQ = codomain_and_points(entry)
    w = (cof * phiP).weil_pairing(cof * phiQ, m)
    b = table.get(w)
    assert b is not None, f"block {k}: pairing value not in the table"
    flag.append(b)

flag = bytes(flag)
assert flag.startswith(b"crypto{") and flag.endswith(b"}")
print()
print(f"FLAG = {flag.decode()}")
