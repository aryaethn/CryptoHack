"""
Nothing Up My Sleeve -- exploit a Dual_EC_DRBG-style RNG where the *player*
chooses the second generator point Q.

RNG.next(): t = seed; s = (t*P).x; seed = s; r = (s*Q).x & (2**240-1)

This is the classic Dual_EC_DRBG construction: state_{k+1} = (state_k * P).x,
output_k = (state_k * Q).x truncated to the low 240 bits.

If we pick Q = P (our "lucky point" equal to the casino's point), then
output_k = (state_k * P).x = state_{k+1} *before truncation*. I.e. every
released output directly reveals the low 240 of the *next* 256-bit state.
Brute-forcing the missing ~16 high bits (~65536 candidates, verified against
a couple of the following observed digits) fully recovers the internal
state, after which every future roulette spin is exactly predictable and we
bet the exact number every round for the +35 payout.
"""
import json
import re

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13387

# P256 (secp256r1) domain parameters
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

TRUNC_BITS = 8 * 30  # 240
TRUNC_MASK = (1 << TRUNC_BITS) - 1
MISSING_BITS = 256 - TRUNC_BITS  # generous upper bound on the missing high bits


def jacobian_double(pt):
    X1, Y1, Z1 = pt
    if Z1 == 0:
        return pt
    delta = (Z1 * Z1) % P
    gamma = (Y1 * Y1) % P
    beta = (X1 * gamma) % P
    alpha = (3 * (X1 - delta) * (X1 + delta)) % P
    X3 = (alpha * alpha - 8 * beta) % P
    Z3 = ((Y1 + Z1) ** 2 - gamma - delta) % P
    Y3 = (alpha * (4 * beta - X3) - 8 * gamma * gamma) % P
    return (X3, Y3, Z3)


def jacobian_add(p1, p2):
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    if Z1 == 0:
        return p2
    if Z2 == 0:
        return p1

    Z1Z1 = (Z1 * Z1) % P
    Z2Z2 = (Z2 * Z2) % P
    U1 = (X1 * Z2Z2) % P
    U2 = (X2 * Z1Z1) % P
    S1 = (Y1 * Z2 * Z2Z2) % P
    S2 = (Y2 * Z1 * Z1Z1) % P

    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)  # point at infinity
        return jacobian_double(p1)

    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    X3 = (R * R - H3 - 2 * U1H2) % P
    Y3 = (R * (U1H2 - X3) - S1 * H3) % P
    Z3 = (Z1 * Z2 * H) % P
    return (X3, Y3, Z3)


def scalar_mult_x(k, x, y):
    """Return ((k*(x,y)).x) as an affine integer."""
    result = (0, 1, 0)  # point at infinity, Jacobian
    addend = (x, y, 1)
    while k:
        if k & 1:
            result = jacobian_add(result, addend)
        addend = jacobian_double(addend)
        k >>= 1
    X, Y, Z = result
    if Z == 0:
        raise ValueError("point at infinity")
    zinv = pow(Z, -1, P)
    return (X * zinv * zinv) % P


def rebase(n, b=37):
    if n < b:
        return [n]
    return [n % b] + rebase(n // b, b)


def digits_to_n(chunk, b=37):
    L = len(chunk)
    n = 0
    for j, d in enumerate(chunk):
        n += d * pow(b, L - 1 - j)
    return n


REDS = {1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36}
BLACKS = {2, 4, 6, 8, 10, 11, 13, 15, 17, 20, 22, 24, 26, 28, 29, 31, 33, 35}


def color_bet(n):
    if n in REDS:
        return "RED"
    if n in BLACKS:
        return "BLACK"
    return "RED"  # n == 0 (green): guaranteed loss either way


CASINO_X = "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
CASINO_Y = "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
Px, Py = int(CASINO_X, 16), int(CASINO_Y, 16)

r = remote(HOST, PORT)
r.recvline()  # before_input banner

# Choose our "lucky point" Q = P (the casino's own point). Then every output
# r_k = (state_k * Q).x = (state_k * P).x = state_{k+1} truncated to 240 bits.
r.sendline(json.dumps({"x": CASINO_X, "y": CASINO_Y}).encode())
resp = json.loads(r.recvline())
print(resp)

CROUPIER_FLAG = "new croupier"

seq = []            # sequence of observed spin digits (base-37), one per round
boundary_rounds = []  # index into seq (1-indexed length) where a cycle ended
cracked = False
next_true_state = None  # once known, (next_true_state * P).x predicts the following state
predicted_digits_buffer = []  # digits of the currently-predicted future cycle, MSB first
pred_ptr = 0

round_no = 1
choice = "RED"  # first bet, before we've seen any spin at all
while True:
    r.sendline(json.dumps({"choice": choice}).encode())
    resp = json.loads(r.recvline())
    if "spin" not in resp:
        print("FINAL:", resp)
        break
    round_no = resp["round"]
    spin = resp["spin"]
    seq.append(spin)
    is_boundary = CROUPIER_FLAG in (resp.get("msg") or "")

    if not cracked:
        if is_boundary:
            start = boundary_rounds[-1] if boundary_rounds else 0
            chunk = seq[start:len(seq)]
            boundary_rounds.append(len(seq))
            n1 = digits_to_n(chunk)

            print(f"[*] Cycle observed (len={len(chunk)}), brute-forcing missing high bits...")
            found = None
            for k in range(1 << MISSING_BITS):
                candidate = n1 | (k << TRUNC_BITS)
                if candidate >= P:
                    continue
                try:
                    nxt = scalar_mult_x(candidate, Px, Py)
                except ValueError:
                    continue
                pred_out = nxt & TRUNC_MASK
                pred_digits = rebase(pred_out)
                if found is None:
                    found = []
                found.append((candidate, nxt, pred_digits))

            print(f"[*] {len(found)} raw candidates before live verification")
            cur_candidates = found
            cracked = "pending"
            verify_idx = 0
    elif cracked == "pending":
        # verify candidates against live spins one digit at a time
        pred_pos = verify_idx
        surviving = []
        for candidate, nxt, pred_digits in cur_candidates:
            if pred_pos < len(pred_digits) and pred_digits[len(pred_digits) - 1 - pred_pos] == spin:
                surviving.append((candidate, nxt, pred_digits))
        cur_candidates = surviving
        verify_idx += 1
        print(f"[*] round {round_no}: {len(cur_candidates)} candidates remain after digit {verify_idx}")
        if len(cur_candidates) == 1:
            _, winning_nxt, winning_pred_digits = cur_candidates[0]
            cracked = True
            # `verify_idx` digits of the *current* (live) cycle have already
            # gone by while we were narrowing candidates -- the rest of this
            # cycle is already known exactly (winning_pred_digits); future
            # cycles are generated by repeatedly applying (*P) to winning_nxt.
            predicted_digits_buffer = winning_pred_digits
            pred_ptr = verify_idx
            next_true_state = winning_nxt
            print(f"[+] RNG fully cracked")

    if cracked is True:
        if pred_ptr >= len(predicted_digits_buffer):
            next_true_state = scalar_mult_x(next_true_state, Px, Py)
            out = next_true_state & TRUNC_MASK
            predicted_digits_buffer = rebase(out)
            pred_ptr = 0
        predicted_spin = predicted_digits_buffer[len(predicted_digits_buffer) - 1 - pred_ptr]
        pred_ptr += 1
        choice = predicted_spin
    else:
        choice = color_bet(spin)

r.close()
