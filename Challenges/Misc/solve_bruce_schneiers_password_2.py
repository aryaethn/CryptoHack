"""
Bruce Schneier's Password: Part 2 -- run with `sage -python` (needs Sage's
LLL). Same int64-overflow idea as Part 1, but this time the check demands
EXACT equality: array.sum() == array.prod() (as well as sum being prime).
A single tunable repetition count can no longer hit an exact 64-bit target
by chance, so this uses real algebra:

* Work in the cyclic group <3> of odd residues mod 2**64 (order 2**62,
  since (Z/2**64)* = {+-1} x <3>). A "2-adic discrete log" dlog3(a) finds k
  with a == (+-1)*3**k via bit-by-bit Hensel lifting, in O(64) steps.
* Restrict every character used (mandatory + filler) to the sign=+1 class,
  so the whole product's dlog is simply the sum of the fillers' individual
  dlog exponents -- turning "product mod 2**64" into a LINEAR problem.
* Pick 3 mandatory chars ('1','A','a', satisfying the digit/upper/lower
  requirement) plus a pool of other sign=+1 odd \\w characters as repeated
  fillers with unknown non-negative counts k_i. For a chosen target prime V
  we need simultaneously:
      exact:    S0 + sum(c_i * k_i)      == V
      modular:  exp(P0) + sum(x_i * k_i) == dlog3(V)   (mod 2**62)
  Solve the exact equation's kernel (integer null space of the c_i vector),
  then solve the *modular* equation restricted to that kernel via a
  standard q-ary lattice + LLL/Babai (this is the part that needs Sage) to
  find a SMALL, hopefully non-negative, solution.
* Try many candidate primes V until one gives an all-non-negative, short
  solution -- V ~ 2*10**3..5*10**4 reliably yields passwords a few hundred
  characters long.
"""
import json

from sage.all import matrix, ZZ, vector, QQ
from Crypto.Util.number import isPrime
from pwn import remote
import random as pyrandom

HOST = "socket.cryptohack.org"
PORT = 13401

MOD = 2**64
ORD = 2**62  # order of <3> mod 2**64


def dlog3(a):
    """a odd. Return (sign, exp) with a == (-1)**sign * 3**exp (mod 2**64)."""
    n = 64
    if a % 2 == 0:
        raise ValueError("even")
    for sign in (0, 1):
        target = (a * (-1) ** sign) % MOD
        k = 0
        current = 1
        for i in range(n - 2):
            m = 1 << (i + 3)
            if m > MOD:
                m = MOD
            if (current % m) != (target % m):
                k |= (1 << i)
                current = (current * pow(3, 1 << i, MOD)) % MOD
        if pow(3, k, MOD) == target:
            return sign, k
    raise ValueError("unreachable")


# build the pool of odd \w characters with sign == 0 (directly a power of 3)
candidates = [chr(c) for c in range(49, 58, 2)]
candidates += [chr(c) for c in range(65, 91, 2)]
candidates += [chr(c) for c in range(97, 123, 2)]

pool = []
for ch in candidates:
    sign, exp = dlog3(ord(ch))
    if sign == 0:
        pool.append((ch, ord(ch), exp))

mandatory = [p for p in pool if p[0] in ('1', 'A', 'a')]
fillers = [p for p in pool if p[0] not in ('1', 'A', 'a')]
m = len(fillers)
c_vec = [f[1] for f in fillers]
x_vec = [f[2] for f in fillers]

S0 = sum(p[1] for p in mandatory)
P0 = 1
for p in mandatory:
    P0 *= p[1]
P0 %= MOD
sign_P0, exp_P0 = dlog3(P0)
assert sign_P0 == 0


def xgcd_(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def extended_gcd_chain(vals):
    g = vals[0]
    coeffs = [1] + [0] * (len(vals) - 1)
    for i in range(1, len(vals)):
        gnew, a, b = xgcd_(g, vals[i])
        coeffs = [a * c for c in coeffs]
        coeffs[i] += b
        g = gnew
    return g, coeffs


g, bez = extended_gcd_chain(c_vec)
assert g == 1

Crow = matrix(ZZ, [c_vec])
Kb = Crow.right_kernel().basis_matrix()  # (m-1) x m, kernel of c_vec
Kb_reduced = Kb.LLL()


def babai_round(target, basis_rows):
    rows_q = [vector(QQ, r) for r in basis_rows if r != 0]
    bstar = []
    for r in rows_q:
        v = r
        for bs in bstar:
            v = v - (r.dot_product(bs) / bs.dot_product(bs)) * bs
        bstar.append(v)
    v = vector(QQ, target)
    coeffs = []
    for i in reversed(range(len(rows_q))):
        c = round(v.dot_product(bstar[i]) / bstar[i].dot_product(bstar[i]))
        v = v - c * rows_q[i]
        coeffs.append(c)
    coeffs.reverse()
    combo = vector(ZZ, [0] * len(target))
    for c, r in zip(coeffs, basis_rows):
        if r != 0:
            combo += c * r
    return combo


def small_modular_solution(A_coeffs, B, M):
    n = len(A_coeffs)
    A0 = A_coeffs[0]
    inv0 = pow(A0, -1, M)
    rows = [[M] + [0] * (n - 1)]
    for i in range(1, n):
        row = [0] * n
        row[0] = (-inv0 * A_coeffs[i]) % M
        row[i] = 1
        rows.append(row)
    Br = matrix(ZZ, rows).LLL()
    s_p = vector(ZZ, [(B * inv0) % M] + [0] * (n - 1))
    combo = babai_round(-vector(QQ, s_p), Br.rows())
    s_final = s_p + combo
    assert (vector(ZZ, A_coeffs).dot_product(s_final)) % M == B % M
    return s_final


def try_password(V):
    sign_V, exp_V = dlog3(V)
    if sign_V != 0:
        return None
    R = V - S0
    D = (exp_V - exp_P0) % ORD

    k_p = vector(ZZ, [b_ * R for b_ in bez])
    shrink = babai_round(-vector(QQ, k_p), Kb_reduced.rows())
    k_p = k_p + shrink
    assert vector(ZZ, c_vec).dot_product(k_p) == R

    x_kp = vector(ZZ, x_vec).dot_product(k_p) % ORD
    B_target = (D - x_kp) % ORD

    kb_rows = list(Kb.rows())
    A_coeffs = [int(vector(ZZ, x_vec).dot_product(vector(ZZ, row))) % ORD for row in kb_rows]

    pivot = next((i for i, a in enumerate(A_coeffs) if a % 2 == 1), None)
    if pivot is None:
        return None
    if pivot != 0:
        A_coeffs[0], A_coeffs[pivot] = A_coeffs[pivot], A_coeffs[0]
        kb_rows[0], kb_rows[pivot] = kb_rows[pivot], kb_rows[0]

    s = small_modular_solution(A_coeffs, B_target, ORD)

    k_final = k_p
    for j in range(len(s)):
        k_final = k_final + s[j] * vector(ZZ, kb_rows[j])

    assert vector(ZZ, c_vec).dot_product(k_final) == R
    assert vector(ZZ, x_vec).dot_product(k_final) % ORD == D
    return list(k_final)


best = None
for _ in range(30000):
    cand = pyrandom.randrange(2 * 10**3, 5 * 10**4) | 1
    if isPrime(cand):
        res = try_password(cand)
        if res is not None and min(res) >= 0:
            s = sum(res)
            if best is None or s < best[1]:
                best = (cand, s, res)

V, total, k_final = best
password = mandatory[0][0] + mandatory[1][0] + mandatory[2][0]
for (ch, _, _), k in zip(fillers, k_final):
    password += ch * k
print(f"[+] password length {len(password)}, target V={V}")

r = remote(HOST, PORT)
r.recvline()
r.sendline(json.dumps({"password": password}).encode())
print(json.loads(r.recvline()))
r.close()
