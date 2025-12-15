#!/usr/bin/env sage

from sage.all import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import json

# ============================================================
# Parameters – adjust BITS to match the challenge script
# ============================================================

P = 2
N = 150    # matrix dimension
BITS = 48  # exponent bit-length (check the original challenge code)

# Kangaroo parameters (tune if needed)
R = 32      # number of jump sizes
DPBITS = 20 # number of bits for "distinguished point" condition

# ============================================================
# I/O helpers for matrices and key derivation
# ============================================================

def load_matrix(fname):
    """
    Load an N x N binary matrix from a file with lines of '0'/'1'.
    Ignore any whitespace.
    """
    rows = []
    with open(fname, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # For the *real* files this should be all 0/1; if your file
            # has '...' in it, that's just a redacted version.
            row = [int(c) for c in line]
            rows.append(row)
    if len(rows) != N:
        raise ValueError("Expected %d rows, got %d" % (N, len(rows)))
    for r in rows:
        if len(r) != N:
            raise ValueError("Row length not %d" % N)
    F2 = GF(2)
    return Matrix(F2, rows)

def matrix_pow(M, e):
    """
    Fast exponentiation of a matrix over GF(2).
    """
    if e < 0:
        raise ValueError("Negative exponent not supported")
    F2 = M.base_ring()
    I = identity_matrix(F2, M.nrows())
    res = I
    base = M
    n = e
    while n > 0:
        if n & 1:
            res = res * base
        base = base * base
        n >>= 1
    return res

def derive_aes_key_from_matrix(M):
    """
    YOU SHOULD MAKE THIS MATCH THE CHALLENGE'S derive_aes_key EXACTLY.

    This implementation assumes:
      - The shared secret is serialized as N*N bits row-major,
      - Packed into bytes MSB-first,
      - Then SHA256 is applied to get a 32-byte key.
    If the challenge uses a different serialization order, copy the exact
    derive_aes_key() from matrix_revolutions.sage instead.
    """
    bits = []
    for i in range(N):
        for j in range(N):
            bits.append(int(M[i, j]))
    # Pack bits into bytes
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte <<= 1
            if i + j < len(bits):
                byte |= bits[i + j]
        b.append(byte)
    h = SHA256.new(bytes(b))
    return h.digest()

# ============================================================
# Pollard's Kangaroo for discrete log in the matrix group
# ============================================================

def matrix_repr_key(M):
    """
    Convert matrix to a string representation suitable as a dict key.
    Slow but simple and safe.
    """
    # Use row-wise '0'/'1' string
    rows = []
    for i in range(N):
        row_bits = ''.join('1' if int(M[i, j]) else '0' for j in range(N))
        rows.append(row_bits)
    return ''.join(rows)

def is_distinguished(M):
    """
    Distinguished point test: check low DPBITS bits of hash(key) == 0.
    """
    k = matrix_repr_key(M)
    h = hash(k)
    return (h & ((1 << DPBITS) - 1)) == 0

def make_jump_table(G, R):
    """
    Create R random jump sizes and their corresponding jump matrices.
    Returns (step_sizes, jump_mats).
    """
    import random
    random.seed(0)   # deterministic for reproducibility
    step_sizes = []
    jump_mats = []
    # Bound for individual step sizes; can be tuned
    MAX_STEP = 1 << 16

    for _ in range(R):
        s = random.randint(1, MAX_STEP)
        step_sizes.append(s)
        jump_mats.append(matrix_pow(G, s))
    return step_sizes, jump_mats

def random_walk_step(X, d, step_sizes, jump_mats):
    """
    Single step in the random walk:
      X -> X * G^{s_i}
      d -> d + s_i
    where i is determined by a hash of X.
    """
    k = matrix_repr_key(X)
    idx = hash(k) & (len(step_sizes) - 1)  # len(step_sizes) must be power of 2 ideally
    s = step_sizes[idx]
    J = jump_mats[idx]
    return (X * J, d + s)

def kangaroo_dlog(G, H, bits=BITS, R=R, dpbits=DPBITS, max_iter=10_000_000):
    """
    Solve discrete log: find x in [0, 2^bits) such that G^x = H
    using Pollard's Kangaroo (Lambda) algorithm, directly in the
    matrix group. No baby-step giant-step is used.
    """
    DPBITS = dpbits
    B = 1 << bits

    # Precompute jump tables
    step_sizes, jump_mats = make_jump_table(G, R)

    # Tame kangaroo starts near upper bound: T_0 = G^B
    X_t = matrix_pow(G, B)
    d_t = B

    # Wild kangaroo starts at H: W_0 = H = G^x
    X_w = H
    d_w = 0

    table = {}  # map repr_key -> d_t
    # We interleave tame and wild steps
    for it in range(max_iter):
        # --- Tame step ---
        X_t, d_t = random_walk_step(X_t, d_t, step_sizes, jump_mats)
        if is_distinguished(X_t):
            key_t = matrix_repr_key(X_t)
            table[key_t] = d_t

        # --- Wild step ---
        X_w, d_w = random_walk_step(X_w, d_w, step_sizes, jump_mats)
        if is_distinguished(X_w):
            key_w = matrix_repr_key(X_w)
            if key_w in table:
                d_t_hit = table[key_w]
                # We have:
                #   G^{d_t_hit} = X_t = X_w = H * G^{d_w} = G^x * G^{d_w}
                # => x = d_t_hit - d_w  (in Z)
                x = d_t_hit - d_w
                if 0 <= x < B:
                    # Optional sanity check:
                    if matrix_pow(G, x) != H:
                        print("[!] Warning: candidate x fails verification, continue search...")
                    else:
                        print(f"[+] Found discrete log: x = {x}")
                        return x

        if it % 10000 == 0 and it > 0:
            print(f"[i] Iteration {it}, table size {len(table)}")

    raise RuntimeError("Kangaroo failed to find discrete log in given iterations")

# ============================================================
# Main solve flow
# ============================================================

def main():
    print("[*] Loading matrices...")
    G = load_matrix("generator.txt")
    A_pub = load_matrix("alice.pub")
    B_pub = load_matrix("bob.pub")

    print("[*] Solving for Alice's private key a such that G^a = A_pub...")
    a = kangaroo_dlog(G, A_pub, bits=BITS, R=R, dpbits=DPBITS)
    print(f"[+] Recovered a = {a}")

    # Optional: sanity check
    if matrix_pow(G, a) != A_pub:
        print("[!] Sanity check failed: G^a != A_pub")
    else:
        print("[*] Sanity check passed: G^a == A_pub")

    print("[*] Computing shared secret S = B_pub^a = G^{ab} ...")
    S = matrix_pow(B_pub, a)

    print("[*] Deriving AES key from shared secret...")
    key = derive_aes_key_from_matrix(S)

    print("[*] Loading ciphertext from flag.enc...")
    with open("flag.enc", "r") as f:
        enc = json.load(f)
    iv = bytes.fromhex(enc["iv"])
    ct = bytes.fromhex(enc["ciphertext"])

    print("[*] Decrypting...")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except ValueError:
        # If padding is wrong, either key derivation or exponent is wrong.
        print("[!] Unpad failed – likely derive_aes_key mismatch or wrong bits.")
    print("[+] Plaintext:", pt)

main()