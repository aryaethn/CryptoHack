from sage.all import *
from pwn import remote
import json
from itertools import product

p = 2**192 - 237
a = -3
b = 1379137549983732744405137513333094987949371790433997718123
order = 6277101735386680763835789423072729104060819681027498877478


def Pohlig_Hellman(P, Q):
    n = P.order()
    results = []
    factors = []
    for prime, exponent in factor(n)[:-1]:
        e = (n//(prime**exponent))
        P_new = e*P
        Q_new = e*Q
        dlog = discrete_log(P_new, Q_new, operation = "+")
        results.append(dlog)
        factors.append(prime**exponent)
        
    return crt(results,factors), prod(factors)


E = EllipticCurve(GF(p), [a, b])

non_square = -1
assert Mod(non_square, p).is_square() == false
twist = E.quadratic_twist(non_square)

E2 = EllipticCurve(GF((p, 2), "k"), [a, b])


P = E2.lift_x(ZZ(randint(1, p)))
while P.order() != E.order():
    P = E2.lift_x(ZZ(randint(1, p)))

Q = E2.lift_x(ZZ(randint(1, p)))
while Q.order() != twist.order():
    Q = E2.lift_x(ZZ(randint(1, p)))

print(f"{P = }")
print(f"{Q = }")

r = remote("socket.cryptohack.org", 13416)
r.recvuntil(b'You have 120 seconds to submit the private key in decimal format.\n')

d_res = []
moduli = []

for point in [P, Q]:
    payload = {"option": "get_pubkey", 'x0': int(point[0])}
    r.sendline(json.dumps(payload).encode())
    public_key = json.loads(r.recvline().decode())
        
    A = E2.lift_x(ZZ(public_key["pubkey"]))
    
    # A = B * d
    d_remainders, modulus = Pohlig_Hellman(A, point)
    d_res.append(d_remainders)
    moduli.append(modulus)


sign_remainders = []
for signs in product([1, -1], repeat=len(d_res)):
    signed = [sign * val for sign, val in zip(signs, d_res)]
    sign_remainders.append(signed)


private_key = []
for d_r in sign_remainders:
    private_key.append(crt(d_r, moduli))
    
for i in private_key:
    print(i)
    payload = {"option": "get_flag", "privkey": int(i)}
    r.sendline(json.dumps(payload).encode())
r.interactive()
