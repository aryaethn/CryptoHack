#!/usr/bin/env python3
# Gauss (Gaussian) lattice reduction in 2D (integer basis)
# Flag = inner product of the reduced basis vectors.

def dot(a, b):
    return a[0] * b[0] + a[1] * b[1]

def norm2(v):
    return dot(v, v)

def sub_mul(v, m, u):
    # v - m*u
    return (v[0] - m * u[0], v[1] - m * u[1])

def nearest_int(num, den):
    """
    Nearest integer to num/den with integer arithmetic.
    Implements ⌊ num/den ⌉ (round-to-nearest), with half-ties rounded away from 0.
    den must be > 0.
    """
    if den <= 0:
        raise ValueError("den must be positive")
    if num >= 0:
        return (num + den // 2) // den
    else:
        return -(((-num) + den // 2) // den)

def gauss_reduce(v1, v2):
    """
    Gaussian lattice reduction (2D).
    Returns a reduced (often called "optimal") basis (v1, v2).
    """
    while True:
        # (a) ensure ||v1|| <= ||v2|| (compare squared norms)
        if norm2(v2) < norm2(v1):
            v1, v2 = v2, v1

        # (b) m = round( (v1·v2) / (v1·v1) )
        den = norm2(v1)
        num = dot(v1, v2)
        m = nearest_int(num, den)

        # (c) if m == 0, done
        if m == 0:
            return v1, v2

        # (d) v2 = v2 - m*v1
        v2 = sub_mul(v2, m, v1)

if __name__ == "__main__":
    v = (846835985, 9834798552)
    u = (87502093, 123094980)

    b1, b2 = gauss_reduce(v, u)

    print("Reduced basis:")
    print("b1 =", b1)
    print("b2 =", b2)

    flag = dot(b1, b2)
    print("FLAG (inner product b1·b2) =", flag)