import math

O = 'inf'


a = 497
b = 1768
p = 9739

def ecc_add(P, Q, a, b, p):
    if P == O:
        return Q
    if Q == O:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if y1 == -y2:
            return O
    if P != Q:
        lam = (y2 - y1) * pow(x2 - x1, -1, p)
    else:
        lam = (3 * x1**2 + a) * pow(2 * y1, -1, p)
    x3 = pow(lam, 2, p) - x1 - x2
    y3 = lam * (x1-x3) - y1
    return (x3 % p, y3 % p)

X = (5274,2841)
Y = (8669,740)

assert ecc_add(X, Y, a, b, p) == (1024,4440)
assert ecc_add(X, X, a, b, p) == (7284,2107)

P = (493,5564)
Q = (1539,4742)
R = (4403,5202)

P2 = ecc_add(P, P, a, b, p)
P2Q = ecc_add(P2, Q, a, b, p)
P2QR = ecc_add(P2Q, R, a, b, p)

# print(P2QR)
