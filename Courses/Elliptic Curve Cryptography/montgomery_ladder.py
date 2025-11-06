from scalar_multiplication import ecc_scalar_multiplication
from ecc_addition import ecc_add
# from sage.all import *

O = 'inf'

def montgomery_double(P, a, b, p):
    if P == O:
        return O
    x1, y1 = P
    alpha = (((3*x1**2 + 2*a*x1 + 1) % p) * pow(2*b*y1, -1, p)) % p
    x3 = (b*pow(alpha, 2, p) - a - 2*x1 % p)%p
    y3 = (alpha * (x1 - x3) - y1 % p)%p
    return (x3, y3)

def montgomery_add(P, Q, a, b, p):
    if P == O:
        return Q
    if Q == O:
        return P
    if P == Q:
        return montgomery_double(P, a, b, p)
    x1, y1 = P
    x2, y2 = Q
    alpha = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (b*pow(alpha, 2, p) - a - x1 - x2)%p
    y3 = (alpha * (x1 - x3) - y1 % p)%p
    return (x3, y3)

## Y^2 = X^3 + aX^2 + X 
b = 1
a = 486662
p = 2**255 - 19

def ecc_montgomery_ladder(P, n, a, b, p):
    R1 = montgomery_double(P, a, b, p)
    R0 = P
    binary_n = bin(n)[2:]
    for i in range(len(binary_n)-2, -1, -1):
        # print(R0, R1, binary_n[i])
        if binary_n[i] == '1':
            R1 = montgomery_add(R0, R1, a, b, p)
            R0 = montgomery_double(R0, a, b, p)
        else:
            R0= montgomery_add(R1, R0, a, b, p)
            R1 = montgomery_double(R1, a, b, p)
    return R0


G_x = 9
G_y2 = (pow(G_x, 3, p) + a* pow(G_x, 2, p) + G_x) % p
G_y = 14781619447589544791020593568409986887264606134616475288964881837755586237401
# print(G_y2)
n_Q = int("1337c0decafe", 16)


P = (G_x, G_y)
# print(montgomery_double(P, a, b, p))
print(ecc_montgomery_ladder(P, n_Q, a, b, p))
# Q = ecc_montgomery_ladder(P, n_Q, a, b, p)
# print(Q)

# (49231350462786016064336756977412654793383964726771892982507420921563002378152 : 12119005339632834459469309411129861912584664210865168553689096898112464563298 : 1)