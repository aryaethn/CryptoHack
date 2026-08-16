"""
L-Win -- LFSR with unknown taps.

FLAG (384 bits) is loaded as the initial 384-bit state of a shift register.
Each clock outputs the leading bit and appends a feedback bit computed by
XORing 4 secret tap positions. After 16*48=768 warm-up clocks (discarded),
2048 output bits are given to us.

Key structural fact: because the register is a pure shift (new bit appended
at the end, old bit popped from the front), state_n[k] == b_{n+k} for all n,k
-- i.e. the state at time n is just the window of 384 consecutive output bits
starting at time n. In particular state_0 (== the FLAG bits) is exactly
b_0..b_383.

We don't know the taps, but Berlekamp-Massey recovers the *minimal linear
recurrence* satisfied by ANY sufficiently long window of the output stream --
equivalent information to the taps, without needing to identify them
explicitly. With that recurrence in hand we can run the (always invertible,
by construction of a minimal connection polynomial) recurrence backward from
the known window at position 768 down to position 0, recovering the flag
bits directly.
"""


def berlekamp_massey(bits):
    """Return (C, L): the minimal connection polynomial (C[0]=1, C[L]=1) of
    degree L such that sum_j C[j]*bits[n-j] == 0 (mod 2) for all valid n."""
    n = len(bits)
    C = [1] + [0] * n
    B = [1] + [0] * n
    L = 0
    m = 1
    b = 1
    for i in range(n):
        d = bits[i]
        for j in range(1, L + 1):
            d ^= C[j] & bits[i - j]
        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            for j in range(0, n - m + 1):
                C[j + m] ^= B[j]
            L = i + 1 - L
            B = T
            b = d
            m = 1
        else:
            for j in range(0, n - m + 1):
                C[j + m] ^= B[j]
            m += 1
    return C[: L + 1], L


with open("output_lwin_given.txt") as f:
    stream = [int(c) for c in f.read().strip()]

C, L = berlekamp_massey(stream)
print(f"[+] Berlekamp-Massey recovered linear complexity L = {L}")
assert C[0] == 1 and C[L] == 1

# sanity check: the recurrence must reproduce the entire observed stream
for i in range(L, len(stream)):
    v = 0
    for j in range(1, L + 1):
        v ^= C[j] & stream[i - j]
    assert v == stream[i], f"recurrence check failed at {i}"
print("[+] recurrence verified against full observed stream")

WARMUP = 16 * 48  # 768
TOTAL = WARMUP + len(stream)

seq = [None] * TOTAL
for i, bit in enumerate(stream):
    seq[WARMUP + i] = bit

# walk the recurrence backward: bits[k] = bits[k+L] xor xor_{j=1}^{L-1} C[j]*bits[k+L-j]
for k in range(WARMUP - 1, -1, -1):
    val = seq[k + L]
    for j in range(1, L):
        val ^= C[j] & seq[k + L - j]
    seq[k] = val

flag_bits = seq[0:384]
flag_int = int("".join(map(str, flag_bits)), 2)
flag = flag_int.to_bytes(48, "big")
print(flag.decode())
