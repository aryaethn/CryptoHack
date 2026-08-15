import json
import random
import string
import time
from hashlib import sha3_256

import sympy
from Crypto.Util.number import bytes_to_long, isPrime, long_to_bytes
from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13431

g = 2
BITS = 1024
SMALL_BOUND = 200_000
SEARCH_POOL = 1000
DEEP_CANDIDATES = 30
TARGET_BITS = 420  # safety margin over the 312-bit (39-byte) target; some
                    # claimed q^e may shrink once we account for g's real order
# max_turns dropped to 4 this time; turn economy (throwaway + useful per
# controlled proof) caps us at only 2 real (seed-controlled) proofs, so we
# need to find 2 EXCEPTIONALLY smooth primes rather than a handful of decent
# ones. Note: this challenge's "c" hash also XORs in an unpredictable
# internal randint, so recomputing c (and hence the r/nonce-reuse route) is
# not viable -- we ignore t/r/c entirely and go straight for y = g^FLAG mod p
# via Pohlig-Hellman, exactly as in the previous challenge.
MAX_USEFUL_PROOFS = 2


def keepalive(r):
    r.sendline(json.dumps({"option": "keepalive"}).encode())
    r.recvline()


def getPrime_sim(N, R):
    while True:
        number = R.getrandbits(N) | 1
        if isPrime(number, randfunc=lambda x: long_to_bytes(R.getrandbits(x))):
            break
    return number


def small_factors(n, bound=SMALL_BOUND):
    factors = []
    d = 2
    while d <= bound and d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1 if d == 2 else 2
    return factors, n


def bsgs(base, target, p, order):
    m = int(order ** 0.5) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = (e * base) % p
    factor = pow(base, -m, p)
    e = target % p
    for i in range(m + 1):
        if e in table:
            return i * m + table[e]
        e = (e * factor) % p
    raise ValueError("bsgs failed")


def actual_q_power(base, p, q, e_claimed):
    """g's order need not have the full claimed q^e -- find the real exponent."""
    h = base
    actual_e = e_claimed
    while actual_e > 0 and pow(h, q ** (actual_e - 1), p) == 1:
        actual_e -= 1
    return actual_e


def pohlig_hellman_prime_power(base, target, p, q, e_claimed):
    e = actual_q_power(base, p, q, e_claimed)
    if e == 0:
        return 0, 0
    n = q ** e
    gamma = pow(base, n // q, p)
    base_inv = pow(base, -1, p)
    x = 0
    for k in range(e):
        exp = n // (q ** (k + 1))
        hk = pow((target * pow(base_inv, x, p)) % p, exp, p)
        d = bsgs(gamma, hk, p, q)
        x += d * (q ** k)
    return x, e


r = remote(HOST, PORT)
banner = r.recvline().decode()
print(banner.strip(), flush=True)
line = r.recvline().decode()
print(line.strip(), flush=True)
nonce = bytes.fromhex(line.split(":")[1].strip())
print("nonce:", nonce.hex(), flush=True)

# --- offline search: which seeds give us a prime p with a highly smooth p-1? ---
print(f"[*] fast trial-division search over {SEARCH_POOL} candidate seeds...", flush=True)
t0 = time.time()
candidates = []
for i in range(SEARCH_POOL):
    seed = i.to_bytes(8, "big")
    R = random.Random(nonce + seed)
    p = getPrime_sim(BITS, R)
    factors, cofactor = small_factors(p - 1)
    bits = sum(f.bit_length() - 1 for f in factors)
    candidates.append({"seed": seed, "p": p, "factors": factors, "cofactor": cofactor, "bits": bits})
    if i % 15 == 0:
        keepalive(r)
print(f"[*] search done in {time.time()-t0:.1f}s", flush=True)

candidates.sort(key=lambda c: -c["bits"])
top = candidates[:DEEP_CANDIDATES]

print(f"[*] deep-factoring the top {DEEP_CANDIDATES} cofactors with Pollard rho/p-1 ...", flush=True)
for c in top:
    t0 = time.time()
    extra = sympy.factorint(c["cofactor"], limit=2 * 10 ** 6)
    for prime, mult in extra.items():
        if prime.bit_length() < 55:  # keep only factors BSGS can handle quickly
            c["factors"].extend([prime] * mult)
    c["bits"] = sum(f.bit_length() - 1 for f in c["factors"])
    print(f"    seed={int.from_bytes(c['seed'],'big')} bits={c['bits']} ({time.time()-t0:.1f}s)", flush=True)
    keepalive(r)

top.sort(key=lambda c: -c["bits"])

# greedy union: maximize *distinct* prime-power coverage using as few candidates as possible
covered = {}  # prime -> exponent
selected = []
for c in top:
    pp = {}
    for f in c["factors"]:
        pp[f] = pp.get(f, 0) + 1
    new_bits = sum((f.bit_length() - 1) for f, e in pp.items() for _ in range(max(0, e - covered.get(f, 0))))
    if new_bits == 0:
        continue
    selected.append((c, pp))
    for f, e in pp.items():
        covered[f] = max(covered.get(f, 0), e)
    total_bits = sum((f.bit_length() - 1) * e for f, e in covered.items())
    print(f"[*] selected seed={int.from_bytes(c['seed'],'big')}, running coverage {total_bits} bits", flush=True)
    if len(selected) >= MAX_USEFUL_PROOFS or total_bits >= TARGET_BITS:
        break

total_bits = sum((f.bit_length() - 1) * e for f, e in covered.items())
print(f"[*] final selection: {len(selected)} primes, {total_bits} bits of coverage", flush=True)
assert total_bits >= 312, "not enough smooth coverage, widen the search"

# --- live phase: spend our turns on exactly these chosen seeds ---
# turn economy: get_proof is the only action that consumes a "turn" (max 12),
# but "refresh" requires your_turn>=2, and after ANY get_proof your_turn only
# goes up by 1 -- so after a *useful* (seed-controlled) proof, your_turn==1,
# too low to refresh again immediately. Each useful proof therefore costs
# one extra throwaway get_proof first to bump your_turn back to >=2.
results = []
for c, pp in selected:
    # throwaway get_proof to make your_turn >= 2 (uncontrolled p, discarded)
    r.sendline(json.dumps({"option": "get_proof"}).encode())
    r.recvline()

    seed_hex = c["seed"].hex()
    r.sendline(json.dumps({"option": "refresh", "seed": seed_hex}).encode())
    resp = json.loads(r.recvline())
    assert "msg" in resp, resp

    r.sendline(json.dumps({"option": "get_proof"}).encode())
    resp = json.loads(r.recvline())
    y = resp["y"]
    print(f"[*] got y for seed={int.from_bytes(c['seed'],'big')}", flush=True)
    results.append((c["p"], y, pp))

# --- Pohlig-Hellman per prime-power, then CRT combine ---
master = {}  # q -> (e, x mod q^e)
for p, y, pp in results:
    for q, e in pp.items():
        n = q ** e
        gexp = (p - 1) // n
        g2 = pow(g, gexp, p)
        y2 = pow(y, gexp, p)
        if g2 == 1:
            continue
        x_qe, e_actual = pohlig_hellman_prime_power(g2, y2, p, q, e)
        if e_actual == 0:
            continue
        cur = master.get(q)
        if cur is None or e_actual > cur[0]:
            master[q] = (e_actual, x_qe)

moduli = [q ** e for q, (e, _) in master.items()]
remainders = [x for _, (e, x) in master.items()]
FLAG_int, M = sympy.ntheory.modular.crt(moduli, remainders)
print(f"[*] recovered FLAG mod {M.bit_length()} bits", flush=True)

flag_transformed = long_to_bytes(int(FLAG_int), 39)
middle = bytes(a ^ b for a, b in zip(flag_transformed[7:-1], nonce))
noisy = flag_transformed[:7] + middle + flag_transformed[-1:]

flag_bytes = bytes(b for b in noisy if chr(b) in string.printable)
print("recovered flag:", flag_bytes)
