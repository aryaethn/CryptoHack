import math
from ecc_addition import ecc_add

O = 'inf'


a = 497
b = 1768
p = 9739

def ecc_scalar_multiplication(P, n, a, b, p):
    R = O

    while n > 0:
        if n % 2 == 1:
            R = ecc_add(R, P, a, b, p)
        P = ecc_add(P, P, a, b, p)
        n = n // 2
    return R


X = (5323,5438)
n = 1337
# print(ecc_scalar_multiplication(X, n, a, b, p))
assert ecc_scalar_multiplication(X, n, a, b, p) == (1089,6931)

P = (2339,2213)
n = 7863

# print(ecc_scalar_multiplication(P, n, a, b, p))