#!/usr/bin/env python3
# Gram–Schmidt (orthogonal basis, NOT orthonormal)

from fractions import Fraction

def dot(a, b):
    return sum(x * y for x, y in zip(a, b))

def norm2(a):
    return dot(a, a)

def smul(c, v):
    return [c * x for x in v]

def vsub(a, b):
    return [x - y for x, y in zip(a, b)]

def gram_schmidt(vs):
    us = []
    for i, v in enumerate(vs):
        u = v[:]  # copy
        for j in range(i):
            uj = us[j]
            mu = dot(v, uj) / norm2(uj)  # μ_ij = (v_i · u_j) / ||u_j||^2
            u = vsub(u, smul(mu, uj))    # u_i = v_i - Σ μ_ij u_j
        us.append(u)
    return us

def to_frac_vec(tup):
    return [Fraction(x) for x in tup]

if __name__ == "__main__":
    v1 = to_frac_vec((4, 1,  3, -1))
    v2 = to_frac_vec((2, 1, -3,  4))
    v3 = to_frac_vec((1, 0, -2,  7))
    v4 = to_frac_vec((6, 2,  9, -5))

    us = gram_schmidt([v1, v2, v3, v4])
    u4 = us[3]

    second_component = u4[1]          # 0-indexed => [1] is the 2nd component
    x = float(second_component)       # “flag is the float value …”
    flag = format(x, ".5g")           # 5 significant figures

    print("u4 =", [str(c) for c in u4])
    print("u4[2nd component] =", x)
    print("FLAG (5 s.f.) =", flag)