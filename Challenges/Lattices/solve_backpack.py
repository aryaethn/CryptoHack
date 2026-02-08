#!/usr/bin/env python3
from ast import literal_eval
from Crypto.Util.number import long_to_bytes

# ---------------- parse output.txt ----------------
with open("output_backpack.txt", "r") as f:
    out = f.read()

pub = literal_eval(out.split("Public key: ")[1].split("\nEncrypted Flag:")[0].strip())
ct  = int(out.split("Encrypted Flag: ")[1].strip())

# ---------------- known flag format ----------------
prefix = b"crypto{"
suffix = b"}"
L = 34  # from source.py: 34 bytes => 272 bits

msg = [None] * L
for i, b in enumerate(prefix):
    msg[i] = b
msg[-1] = suffix[0]

def bit_index_of_bytepos(bytepos_from_start: int, bit_in_byte: int) -> int:
    # bytes_to_long is big-endian; bit 0 is LSB of the integer
    return 8 * ((L - 1) - bytepos_from_start) + bit_in_byte

# subtract known contributions from ciphertext
contrib = 0
for j, val in enumerate(msg):
    if val is None:
        continue
    for k in range(8):
        if (val >> k) & 1:
            idx = bit_index_of_bytepos(j, k)
            contrib += pub[idx]

target = ct - contrib

# unknown bits correspond to indices 8..215 (208 bits)
weights = pub[8:216]
n = len(weights)
assert n == 208

# ---------------- LLL attack ----------------
# We want x in {0,1}^n s.t. sum x_i * w_i = target
#
# Use embedding:
#   Basis is (n+1)x(n+1)
#   For i=0..n-1: row i is e_i with last entry = w_i
#   Last row:     [1/2, 1/2, ..., 1/2, target]
#
# Multiply by 2 to avoid fractions:
#   For i:  row i has 2 on diag, last = 2*w_i
#   Last:   all ones, last = 2*target
#
# Then a vector corresponding to solution has first coords ±1 and last coord 0.
#
# We then decode sign pattern and VERIFY.

def solve_subset_sum_fpylll(weights, target):
    from fpylll import IntegerMatrix, LLL

    # Try multiple scalings by scaling the LAST COLUMN only.
    # This helps LLL focus on the ±1 pattern.
    #
    # Instead of multiplying last column by huge N (which can create nasty bases),
    # we use moderate powers of 2 and rely on low density + verification.
    scales = [1, 2, 4, 8, 16, 32, 64, 128]

    for S in scales:
        M = IntegerMatrix(n + 1, n + 1)

        # rows 0..n-1
        for i in range(n):
            M[i, i] = 2
            M[i, n] = 2 * S * weights[i]

        # last row
        for i in range(n):
            M[n, i] = 1
        M[n, n] = 2 * S * target

        # LLL reduce
        LLL.reduction(M)

        # collect some shortest vectors from the reduced basis
        rows = [[int(M[r, c]) for c in range(n + 1)] for r in range(n + 1)]
        rows.sort(key=lambda v: sum(x*x for x in v))
        rows = rows[:40]  # keep a bunch of short ones

        # Try decoding from basis vectors directly AND small combos of them.
        # Small combos often produce the exact "last=0" relation.
        candidates = []

        # direct rows
        candidates.extend(rows)

        # small combos: v_i ± v_j, v_i ± v_j ± v_k
        for i in range(min(15, len(rows))):
            for j in range(i+1, min(15, len(rows))):
                vi, vj = rows[i], rows[j]
                candidates.append([vi[t] + vj[t] for t in range(n+1)])
                candidates.append([vi[t] - vj[t] for t in range(n+1)])
        for i in range(min(10, len(rows))):
            for j in range(i+1, min(10, len(rows))):
                for k in range(j+1, min(10, len(rows))):
                    vi, vj, vk = rows[i], rows[j], rows[k]
                    candidates.append([vi[t] + vj[t] + vk[t] for t in range(n+1)])
                    candidates.append([vi[t] + vj[t] - vk[t] for t in range(n+1)])
                    candidates.append([vi[t] - vj[t] + vk[t] for t in range(n+1)])
                    candidates.append([vi[t] - vj[t] - vk[t] for t in range(n+1)])

        # decode and verify
        def try_decode(v):
            # Expect first coords near ±1 (or small integers)
            # We'll interpret sign as bit and VERIFY subset-sum exactly.
            for one_if_positive in (True, False):
                bits = [1 if (x > 0) == one_if_positive else 0 for x in v[:-1]]
                s = sum(b*w for b, w in zip(bits, weights))
                if s == target:
                    return bits
            return None

        for v in candidates:
            bits = try_decode(v)
            if bits is not None:
                return bits

    return None

bits_unknown = solve_subset_sum_fpylll(weights, target)
if bits_unknown is None:
    raise RuntimeError("No valid solution found with LLL-only scales. Add more scales or use Sage.")

# ---------------- rebuild full 272-bit flag ----------------
full_bits = [0] * 272
full_bits[8:216] = bits_unknown

# fill known bytes bits
for j, val in enumerate(msg):
    if val is None:
        continue
    for k in range(8):
        idx = bit_index_of_bytepos(j, k)
        full_bits[idx] = (val >> k) & 1

# pack bits into integer
m = 0
for i in range(271, -1, -1):
    m = (m << 1) | full_bits[i]

pt = long_to_bytes(m)
print(pt)