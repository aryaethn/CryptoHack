from collections import namedtuple
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
from sage.all import *

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# The point at infinity (origin for the group law).
O = 'Origin'


def check_point(P):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P, Q):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P, n):
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


def public_key():
    d = bytes_to_long(FLAG)
    return double_and_add(G, d)


p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
gy = 225987949353410341392975247044711665782695329311463646299187580326445253608
G = Point(gx, gy)

Q = Point(2582928974243465355371953056699793745022552378548418288211138499777818633265, 2421683573446497972507172385881793260176370025964652384676141384239699096612)

rem = (G.y ** 2 - Q.y ** 2 - G.x**3 + Q.x ** 3) %p
q = G.x - Q.x
a = (rem * pow(q, -1, p)) %p
b = (G.y**2 - G.x**3 - a * G.x) % p

# print("a: ", a, " b: ", b)


R = PolynomialRing(GF(p), 'x') # Polynomial ring of polynomials in x with rational coefficients
g = R.gen()

f = g**3 + a * g + b
roots = f.roots()
# print(roots)

root2 = roots[0][0]
root3 = roots[1][0]

f2 = f.subs(x = g + root2)
f3 = f.subs(x = g + root3)

# print(f2.factor())
# print(f3.factor())

t2 = GF(p)(4063410388559334897980342709342612042350324567872047551521081480287204886243).square_root()
t3 = GF(p)(305179796174210822247618473361747316085422620437271958999235012896334193460).square_root()

# print(t2)
# print(t3)

Q3x, Q3y = (Q.x - root3, Q.y)
G3x, G3y = (G.x - root3, G.y)

p3 = (Q3y + t3*Q3x)/(Q3y - t3*Q3x) % p
q3 = (G3y + t3*G3x)/(G3y - t3*G3x) % p

try:
    d3 = long_to_bytes(discrete_log(p3, q3))
except:
    d3 = None
print(d3)

