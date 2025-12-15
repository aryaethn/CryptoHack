#!/usr/bin/env sage -python3
import json, socket, time
from sage.all import *

HOST = "socket.cryptohack.org"
PORT = 13418

# === from 13418.py ===
modulus = Integer("22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651")
a = Integer(-3)
b = Integer("2697448053935541741976221051345108825177671050689533270507")
order = Integer("4782850957738000717885060297297408935631027604045525430677")

# === known factorization of modulus (two primes; corrected p has leading 47...) ===
p = Integer("4782850957738000717885060297350722702854694354378697989111")
q = Integer("4796464665474109238546017500238174976861701183900526078141")
if p*q != modulus:
    if q*p == modulus:
        p, q = q, p
    else:
        raise ValueError("p*q != modulus. Fix p/q.")

# === group sizes over F_p and F_q (from your message) ===
curve_order_p = Integer(2 * 3 * 17 * 127 * 1579 * 173909 * 11999928650382997 * 112046966532895482724073182397)
twist_order_p = Integer(2 * 3 * 47 * 6761 * 12601 * 1090597 * 4253999952883937 * 42910147995890862215199101)

curve_order_q = Integer(2 * (3**2) * 19 * 64805991281 * 216411325660166853456562009211053305944100971)
twist_order_q = Integer(2 * 3 * 7 * 31 * 193718429 * 19016882663263246861783365416821041624899221099)

Eord_p2 = curve_order_p * twist_order_p
Eord_q2 = curve_order_q * twist_order_q

# We target ~174 CRT bits => remaining ~2^18 candidates to brute-force.
# p-side: lots of small factors (fast)
FACTORS_P = [4, 9, 17, 47, 127, 1579, 6761, 12601, 173909, 1090597]
# q-side: include 28-bit and 36-bit factors, solved by Pollard-Rho (constant memory)
FACTORS_Q = [4, 27, 7, 19, 31, 193718429, 64805991281]

# ----------------- raw socket JSON line protocol (banner-safe) -----------------
def sock_send_line(sock, obj):
    msg = (json.dumps(obj) + "\n").encode()
    sock.sendall(msg)

def sock_recv_line(sock, buf):
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("Server closed connection")
        buf += chunk
    line, buf = buf.split(b"\n", 1)
    return line.decode(errors="replace"), buf

def sock_recv_json_skip_banner(sock, buf, max_lines=200):
    for _ in range(max_lines):
        line, buf = sock_recv_line(sock, buf)
        s = line.strip()
        if not s:
            continue
        if not s.startswith("{"):
            # banner / plain text
            continue
        return json.loads(s), buf
    raise RuntimeError("Did not receive JSON from server (too many banner lines?)")

def connect():
    sock = socket.socket()
    sock.connect((HOST, PORT))
    buf = b""
    # Read and print banner lines that arrive immediately (optional)
    t_end = time.time() + 0.2
    sock.setblocking(False)
    try:
        while time.time() < t_end:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except BlockingIOError:
                break
    finally:
        sock.setblocking(True)

    # print any already-received banner lines
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        s = line.decode(errors="replace").rstrip("\n")
        if s and not s.strip().startswith("{"):
            print(s)

    return sock, buf

def get_pubkey(sock, buf, x0):
    sock_send_line(sock, {"option": "get_pubkey", "x0": int(x0)})
    resp, buf = sock_recv_json_skip_banner(sock, buf)
    if "error" in resp:
        raise RuntimeError(resp["error"])
    return Integer(resp["pubkey"]), buf

def submit_key(sock, buf, priv):
    sock_send_line(sock, {"option": "get_flag", "privkey": int(priv)})
    resp, buf = sock_recv_json_skip_banner(sock, buf)
    return resp

# ----------------- exact scalarmult from 13418.py -----------------
def inv_mod_int(x, mod):
    return pow(int(x) % int(mod), -1, int(mod))

def dbl_xz(X1, Z1, mod):
    XX = (X1 * X1) % mod
    ZZ = (Z1 * Z1) % mod
    A  = (2 * ((X1 + Z1) * (X1 + Z1) - XX - ZZ)) % mod
    aZZ = (int(a) * ZZ) % mod
    X3 = ((XX - aZZ) * (XX - aZZ) - 2 * int(b) * A * ZZ) % mod
    Z3 = (A * (XX + aZZ) + 4 * int(b) * (ZZ * ZZ % mod)) % mod
    return X3, Z3

def diffadd_xz(X1, Z1, X2, Z2, x0, mod):
    X1Z2 = (X1 * Z2) % mod
    X2Z1 = (X2 * Z1) % mod
    Z1Z2 = (Z1 * Z2) % mod
    T = (X1Z2 + X2Z1) % mod
    T = (T * ((X1 * X2 + int(a) * Z1Z2) % mod)) % mod
    Z3 = (X1Z2 - X2Z1) % mod
    Z3 = (Z3 * Z3) % mod
    X3 = (2 * T + 4 * int(b) * (Z1Z2 * Z1Z2 % mod) - (x0 % mod) * Z3) % mod
    return X3, Z3

def scalarmult_xonly(scalar, x0, mod):
    scalar = int(scalar)
    x0 = int(x0) % int(mod)
    mod = int(mod)

    R0X, R0Z = x0, 1
    R1X, R1Z = dbl_xz(R0X, R0Z, mod)

    n = scalar.bit_length()
    pbit = 0
    bit = 0

    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit ^= bit
        if pbit:
            R0X, R1X = R1X, R0X
            R0Z, R1Z = R1Z, R0Z

        R1X, R1Z = diffadd_xz(R0X, R0Z, R1X, R1Z, x0, mod)
        R0X, R0Z = dbl_xz(R0X, R0Z, mod)
        pbit = bit

    if bit:
        R0X, R0Z = R1X, R1Z

    try:
        zinv = inv_mod_int(R0Z, mod)
    except ValueError:
        return None
    return (R0X * zinv) % mod

# ----------------- CRT -----------------
def crt_pair(a1, m1, a2, m2):
    a1 = Integer(a1); m1 = Integer(m1)
    a2 = Integer(a2); m2 = Integer(m2)
    g = gcd(m1, m2)
    if (a2 - a1) % g != 0:
        raise ValueError("Inconsistent CRT system")
    l = lcm(m1, m2)
    m1p = m1 // g
    m2p = m2 // g
    t = ((a2 - a1) // g) * inverse_mod(m1p, m2p)
    a = a1 + m1 * t
    return (a % l, l)

# ----------------- Pollard-Rho DLP (prime or factored composite) -----------------
def pollard_rho_dlog_prime(P, Q, r, max_seconds=25):
    r = Integer(r)

    def part(X):
        if X.is_zero():
            return 0
        return int(Integer(X[0]) % 3)

    def step(X, A, B):
        c = part(X)
        if c == 0:
            return X + P, (A + 1) % r, B
        elif c == 1:
            return X + X, (2*A) % r, (2*B) % r
        else:
            return X + Q, A, (B + 1) % r

    start = time.time()
    while True:
        A0 = Integer(randrange(r))
        B0 = Integer(randrange(r))
        X0 = A0*P + B0*Q

        x1, a1, b1 = X0, A0, B0
        x2, a2, b2 = X0, A0, B0

        while True:
            if time.time() - start > max_seconds:
                raise TimeoutError("Pollard-Rho time budget exceeded")

            x1, a1, b1 = step(x1, a1, b1)
            x2, a2, b2 = step(*step(x2, a2, b2))

            if x1 == x2:
                num = (a1 - a2) % r
                den = (b2 - b1) % r
                if den == 0:
                    break
                x = (num * inverse_mod(den, r)) % r
                if x*P == Q:
                    return x
                break

def dlog_mod_k(Eord, P, Q, k):
    """
    Solve d mod k in subgroup via projection by cofactor Eord/k.
    Handles Q vs -Q ambiguity (lift_x).
    Uses:
      - brute for tiny k
      - Sage discrete_log for <= ~25 bits
      - Pollard-Rho for bigger (constant memory)
    """
    k = Integer(k)
    cof = Eord // k
    Pk = cof * P
    Qk = cof * Q
    if Pk.is_zero():
        raise ValueError("Pk=0 (k not usable for this basepoint)")

    # try both lifts
    candidates_Q = [Qk, -Qk]

    if int(k) <= 2000:
        for QQ in candidates_Q:
            T = Pk.parent()(0)
            for x in range(int(k)):
                if T == QQ:
                    return Integer(x)
                T += Pk
        raise ValueError("no dlog (tiny)")

    # moderate sizes: BSGS ok
    if k.nbits() <= 25:
        for QQ in candidates_Q:
            try:
                return Integer(discrete_log(QQ, Pk, ord=k, operation="+"))
            except Exception:
                pass

    # large: Pollard-Rho
    if is_prime(k):
        for QQ in candidates_Q:
            try:
                return Integer(pollard_rho_dlog_prime(Pk, QQ, k, max_seconds=25))
            except Exception:
                pass
        raise ValueError("Pollard-Rho failed (prime)")

    # composite: factor and PH recursively
    fac = factor(k)
    d_acc = Integer(0)
    m_acc = Integer(1)
    for prime, exp in fac:
        pe = Integer(prime)**Integer(exp)
        dk = dlog_mod_k(Eord, P, Q, pe)
        d_acc, m_acc = crt_pair(d_acc, m_acc, dk, pe)
    return d_acc

def solve_modulus_side(r, x0, pub_r, Eord_r2, factors):
    Fr = GF(r)
    Fr2 = GF(r**2, name="u")
    E = EllipticCurve(Fr2, [Fr2(a), Fr2(b)])
    P = E.lift_x(Fr2(Fr(x0)))
    Q = E.lift_x(Fr2(Fr(pub_r)))

    d_acc = Integer(0)
    m_acc = Integer(1)
    used = []

    for k in factors:
        try:
            dk = dlog_mod_k(Eord_r2, P, Q, Integer(k))
            d_acc, m_acc = crt_pair(d_acc, m_acc, dk, Integer(k))
            used.append(int(k))
        except Exception:
            continue

    return d_acc, m_acc, used

def choose_x0(limit=5000):
    """
    Pick x0 such that projections for big q-factors are non-zero (so DLP is solvable).
    """
    Fr2q = GF(q**2, name="uq")
    Eq = EllipticCurve(Fr2q, [Fr2q(a), Fr2q(b)])
    for x0 in range(1, limit + 1):
        Pq = Eq.lift_x(Fr2q(GF(q)(x0)))
        ok = True
        for k in [193718429, 64805991281]:
            cof = Eord_q2 // Integer(k)
            if (cof * Pq).is_zero():
                ok = False
                break
        if ok:
            return Integer(x0)
    raise RuntimeError("No suitable x0 found; increase limit")

def brute_force_finish(pubN, x0, d_mod, M):
    """
    We know priv in [0, order/2] and priv ≡ ±d_mod (mod M). Enumerate and verify by scalarmult.
    """
    pubN = int(pubN)
    x0 = int(x0)
    M = int(M)
    half = int(order // 2)

    residues = [int(d_mod % M), int((-d_mod) % M)]
    residues = list(dict.fromkeys(residues))

    for base in residues:
        if base > half:
            continue
        t_max = (half - base) // M
        for t in range(t_max + 1):
            cand = base + t * M
            y = scalarmult_xonly(cand, x0, modulus)
            if y is not None and int(y) == pubN:
                return Integer(cand)
    return None

def main():
    x0 = choose_x0()
    print(f"[*] Using x0 = {x0}")

    sock, buf = connect()
    try:
        pub, buf = get_pubkey(sock, buf, x0)
        pub_p = pub % p
        pub_q = pub % q

        t0 = time.time()

        dp, mp, used_p = solve_modulus_side(p, x0, pub_p, Eord_p2, FACTORS_P)
        dq, mq, used_q = solve_modulus_side(q, x0, pub_q, Eord_q2, FACTORS_Q)

        d_mod, M = crt_pair(dp, mp, dq, mq)

        print(f"[*] p-used: {used_p}")
        print(f"[*] q-used: {used_q}")
        print(f"[*] CRT bits: {M.nbits()}  (order bits: {order.nbits()})")

        priv = brute_force_finish(pub, x0, d_mod, M)
        if priv is None:
            raise RuntimeError("Bruteforce did not find a key; rerun (different x0) or increase x0 search limit.")

        print(f"[*] Found privkey = {priv}")
        print(f"[*] Solve time (post-query): {time.time() - t0:.2f}s")

        resp = submit_key(sock, buf, priv)
        print(resp)

    finally:
        try:
            sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()