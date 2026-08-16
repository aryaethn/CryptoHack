"""
Bit by Bit -- two stacked bugs in the source:

1. Operator precedence: `me = padding << 1 + m % 2` parses as
   `padding << (1 + m % 2)`, NOT `(padding << 1) + m % 2` as presumably
   intended. So me = padding * 2**(1+bit) -- a pure multiplication by a
   known power of two, not an additive LSB embedding at all.

2. `padding = pow(256, e, q) = 2**(8e) mod q` is *always* an EVEN power of
   2, hence always a quadratic residue mod q, regardless of the secret
   exponent e.

3. The ElGamal generator g is itself a quadratic residue mod q (checked
   directly: g**((q-1)//2) % q == 1). That means h = g**x and c1 = g**y are
   ALWAYS quadratic residues too, for any secret x, y -- ElGamal doesn't
   hide quadratic residuosity when the generator is a QR, a classic design
   flaw.

Putting it together: Legendre(c2) = Legendre(h)**y * Legendre(me)
                                   = 1 * Legendre(padding) * Legendre(2)**(1+bit)
                                   = Legendre(2)**(1+bit)   (since padding is always QR)

2 is a non-residue mod q (Legendre(2) = -1), so Legendre(c2) = (-1)**(1+bit):
bit=0 -> Legendre(c2) = -1 (non-residue); bit=1 -> Legendre(c2) = +1 (residue).
The secret key and c1 are never even needed -- c2's quadratic residuosity
alone reveals every bit of the flag.
"""
import re

from Crypto.Util.number import long_to_bytes

q = 117477667918738952579183719876352811442282667176975299658506388983916794266542270944999203435163206062215810775822922421123910464455461286519153688505926472313006014806485076205663018026742480181999336912300022514436004673587192018846621666145334296696433207116469994110066128730623149834083870252895489152123

with open("output_bit_by_bit_given.txt") as f:
    text = f.read()

c2_values = [int(x, 16) for x in re.findall(r"c2=(0x[0-9a-f]+)", text)]
print(f"[+] parsed {len(c2_values)} ciphertexts")

m = 0
for i, c2 in enumerate(c2_values):
    legendre = pow(c2, (q - 1) // 2, q)
    bit = 1 if legendre == 1 else 0
    m |= bit << i

flag = long_to_bytes(m)
print(flag.decode())
