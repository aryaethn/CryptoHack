"""
Jeff's LFSR -- a Geffe generator: three LFSRs (19, 27, 23 bits, all taps
public), combined as output = LFSR2.bit() if LFSR1.bit() else LFSR3.bit().

The Geffe generator is a textbook-broken combiner: conditioned on the
(unknown) selector bit a_i, the output EXACTLY equals either LFSR2's or
LFSR3's own bit at that step -- no noise at all, just an unknown 50/50 split
of which register is "speaking" at each step.

Attack: brute-force LFSR1's 19-bit initial state (only 2**19 = 524288
candidates -- cheap). For each guess we get a full 256-bit hypothesis for
which positions reveal LFSR2 vs LFSR3. Because LFSR2/LFSR3's taps are known,
each output bit is a KNOWN linear function (over GF(2)) of that register's
27/23-bit initial state. Under the (hopefully correct) partition this gives
a heavily overdetermined (~128 equations for 27 or 23 unknowns) linear
system; solve it with incremental GF(2) Gaussian elimination that aborts the
instant it hits a contradiction. A wrong LFSR1 guess produces a scrambled,
almost-certainly-inconsistent system and gets rejected almost immediately;
the correct guess solves cleanly for both LFSR2 and LFSR3 simultaneously.
"""

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("output_jeffs_lfsr_given.txt") as f:
    lines = f.read().splitlines()

observed = eval(lines[0])
data = eval(lines[1])
iv = bytes.fromhex(data["iv"])
encrypted_flag = bytes.fromhex(data["encrypted_flag"])

STEPS = len(observed)

D1, TAPS1 = 19, [19, 18, 17, 14]
D2, TAPS2 = 27, [27, 26, 25, 22]
D3, TAPS3 = 23, [23, 22, 20, 18]

MASK19 = (1 << D1) - 1
T1 = [D1 - x for x in TAPS1]  # [0, 1, 2, 5]
# bit positions in our packed-int encoding (bit (D1-1-p) == self._s[p])
BITPOS1 = [D1 - 1 - p for p in T1]  # [18, 17, 16, 13]


def clock1(s):
    b18 = (s >> BITPOS1[0]) & 1
    b17 = (s >> BITPOS1[1]) & 1
    b16 = (s >> BITPOS1[2]) & 1
    b13 = (s >> BITPOS1[3]) & 1
    newbit = b18 ^ b17 ^ b16 ^ b13
    return ((s << 1) & MASK19) | newbit, b18


def build_masks(d, taps, steps):
    t = [d - x for x in taps]
    state = [1 << k for k in range(d)]
    masks = []
    for _ in range(steps):
        masks.append(state[0])
        newbit = 0
        for p in t:
            newbit ^= state[p]
        state = state[1:] + [newbit]
    return masks


def try_solve(eqs, nbits):
    pivots = {}
    for mask, target in eqs:
        m, t = mask, target
        stored = False
        while m:
            p = m.bit_length() - 1
            entry = pivots.get(p)
            if entry is None:
                pivots[p] = (m, t)
                stored = True
                break
            pm, pt = entry
            m ^= pm
            t ^= pt
        if not stored and m == 0 and t == 1:
            return None
    if len(pivots) < nbits:
        return None
    return pivots


def extract_state(pivots, nbits):
    piv = dict(pivots)
    order = sorted(piv.keys(), reverse=True)
    for p in order:
        m, t = piv[p]
        for p2 in piv:
            if p2 == p:
                continue
            m2, t2 = piv[p2]
            if (m2 >> p) & 1:
                piv[p2] = (m2 ^ m, t2 ^ t)
    bits = [0] * nbits
    for p in range(nbits):
        m, t = piv[p]
        assert m == (1 << p)
        bits[p] = t
    return bits


masks2 = build_masks(D2, TAPS2, STEPS)
masks3 = build_masks(D3, TAPS3, STEPS)

found = None
for candidate in range(1 << D1):
    s = candidate
    a_bits = [0] * STEPS
    for i in range(STEPS):
        s, b = clock1(s)
        a_bits[i] = b

    eqs2 = [(masks2[i], observed[i]) for i in range(STEPS) if a_bits[i] == 1]
    p2 = try_solve(eqs2, D2)
    if p2 is None:
        continue

    eqs3 = [(masks3[i], observed[i]) for i in range(STEPS) if a_bits[i] == 0]
    p3 = try_solve(eqs3, D3)
    if p3 is None:
        continue

    found = (candidate, p2, p3)
    print(f"[+] Candidate LFSR1 state found: {candidate}")
    break

if found is None:
    raise SystemExit("no candidate found -- something is wrong")

candidate, p2, p3 = found
state1_bits = [int(c) for c in format(candidate, f"0{D1}b")]
state2_bits = extract_state(p2, D2)
state3_bits = extract_state(p3, D3)

key_bits = "".join(map(str, state1_bits + state2_bits + state3_bits))
assert len(key_bits) == 69
key_int = int(key_bits, 2)
print("[+] Recovered key:", key_int)

# sanity check: replicate the full Jeff generator and compare exactly
s1, s2, s3 = state1_bits[:], state2_bits[:], state3_bits[:]


def clock(s, taps):
    d = len(s)
    t = [d - x for x in taps]
    b = s[0]
    newbit = 0
    for p in t:
        newbit ^= s[p]
    s[:] = s[1:] + [newbit]
    return b


regenerated = []
for _ in range(STEPS):
    b1 = clock(s1, TAPS1)
    b2 = clock(s2, TAPS2)
    b3 = clock(s3, TAPS3)
    regenerated.append(b2 if b1 else b3)

assert regenerated == observed, "regenerated stream mismatch!"
print("[+] Verified: regenerated stream matches observed output exactly")

sha1 = hashlib.sha1()
sha1.update(str(key_int).encode("ascii"))
aes_key = sha1.digest()[:16]

cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(encrypted_flag), 16)
print(flag.decode())
