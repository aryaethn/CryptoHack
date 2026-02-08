#!/usr/bin/env python3
import re
import math
from Crypto.Util.number import inverse, long_to_bytes

OUTPUT_FILE = "output_find_the_lattice.txt"

def dot(u, v):
    return u[0]*v[0] + u[1]*v[1]

def norm2(v):
    return dot(v, v)

def gauss_reduce(b1, b2):
    """
    2D Gaussian lattice reduction.
    Returns a reduced basis (v1, v2) where v1 is (typically) a shortest vector.
    """
    b1 = [int(b1[0]), int(b1[1])]
    b2 = [int(b2[0]), int(b2[1])]

    while True:
        # Ensure ||b1|| <= ||b2||
        if norm2(b2) < norm2(b1):
            b1, b2 = b2, b1

        # Nearest integer to projection coefficient
        mu = round(dot(b1, b2) / norm2(b1))

        # If mu == 0, we're done
        if mu == 0:
            return (tuple(b1), tuple(b2))

        # Reduce b2
        b2 = [b2[0] - mu*b1[0], b2[1] - mu*b1[1]]

def parse_output(path):
    s = open(path, "r", encoding="utf-8").read()
    q = int(re.search(r"Public key:\s*\((\d+),", s).group(1))
    h = int(re.search(r"Public key:\s*\(\d+,\s*(\d+)\)", s).group(1))
    e = int(re.search(r"Encrypted Flag:\s*(\d+)", s).group(1))
    return q, h, e

def decrypt(q, h, e):
    # Lattice basis that contains the short vector (g, f)
    b1 = (q, 0)
    b2 = (h, 1)

    v1, v2 = gauss_reduce(b1, b2)

    # The shortest vector is usually v1, but let's be safe.
    short = v1 if norm2(v1) <= norm2(v2) else v2

    g = abs(short[0])
    f = abs(short[1])

    # Sanity check: f*h ≡ g (mod q)
    if (f*h - g) % q != 0:
        # Sometimes you might get (f, g) or sign flips; try swapping.
        g2, f2 = f, g
        if (f2*h - g2) % q == 0:
            g, f = g2, f2
        else:
            raise ValueError("Recovered vector doesn't satisfy f*h ≡ g (mod q).")

    # Decrypt (matches the visible decrypt logic in the challenge)
    a = (f * e) % q
    m = (a * inverse(f, g)) % g
    return long_to_bytes(m)

def main():
    q, h, e = parse_output(OUTPUT_FILE)
    flag = decrypt(q, h, e)
    print(flag.decode(errors="replace"))

if __name__ == "__main__":
    main()