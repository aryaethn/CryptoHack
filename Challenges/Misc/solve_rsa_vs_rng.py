import json

from Crypto.Util.number import inverse, isPrime, long_to_bytes

MOD = 2**512
A = 2287734286973265697461282233387562018856392913150345266314910637176078653625724467256102550998312362508228015051719939419898647553300561119192412962471189
B = 4179258870716283142348328372614541634061596292364078137966699610370755625435095397634562220121158928642693078147104418972353427207082297056885055545010537

data = json.load(open("flag_rsa_vs_rng.enc"))
N = data["N"]
E = data["E"]
ct = int(data["ciphertext"], 16)

# P and Q are two later outputs of the same LCG (state -> A*state+B mod 2**512),
# separated by some unknown number of skipped composite states `d`.
# For a fixed skip d, Q = (a_d * P + c_d) mod 2**512, where the transform
# T_d(x) = a_d*x + c_d is the d-fold composition of T(x) = A*x + B.
#
# Because the modulus is a power of two, that "mod 2**512" causes no trouble:
# reducing an integer mod 2**512 and then mod 2**k (k <= 512) is the same as
# reducing it mod 2**k directly. So for every k <= 512:
#   N = P*Q  =>  N ≡ a_d*P^2 + c_d*P  (mod 2**k)
# which lets us recover P bit-by-bit via Hensel lifting on this quadratic.


def hensel_solve(a, c, n, bits, cap=64):
    def f(x, mod):
        return (a * x * x + c * x - n) % mod

    if f(1, 2) != 0:
        return []

    candidates = [1]
    for k in range(1, bits):
        mod_next = 1 << (k + 1)
        bitk = 1 << k
        nxt = []
        for x in candidates:
            for cand in (x, x + bitk):
                if f(cand, mod_next) == 0:
                    nxt.append(cand)
        candidates = nxt
        if not candidates:
            return []
        if len(candidates) > cap:
            return []
    return candidates


a_d, c_d = A, B  # transform for skip d=1
found = None
d = 1
MAX_D = 5000
while d <= MAX_D:
    for P in hensel_solve(a_d, c_d, N, 512):
        if P and N % P == 0:
            Q = N // P
            if isPrime(P) and isPrime(Q):
                found = (P, Q, d)
                break
    if found:
        break
    # advance transform to skip d+1: T_{d+1}(x) = A*T_d(x) + B
    a_d, c_d = (A * a_d) % MOD, (A * c_d + B) % MOD
    d += 1
    if d % 200 == 0:
        print(f"[*] tried up to d={d}, no factorization yet")

if not found:
    raise SystemExit("failed to factor N within search bound")

P, Q, d = found
print(f"[+] Factored N with skip d={d}")
print("P =", P)
print("Q =", Q)

phi = (P - 1) * (Q - 1)
dec = inverse(E, phi)
pt = pow(ct, dec, N)
flag = long_to_bytes(pt)
print(flag.decode())
