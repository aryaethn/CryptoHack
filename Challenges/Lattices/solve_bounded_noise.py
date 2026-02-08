#!/usr/bin/env python3
import json
import ast
import random
from pathlib import Path

import numpy as np

Q = 65537          # modulus
N = 25             # secret length
FLAG_LEN = 49      # from the challenge code: len(b"crypto{...}") == 49

def inv_mod(M: np.ndarray, q: int) -> np.ndarray | None:
    """
    Invert an NxN matrix mod q using Gauss-Jordan elimination.
    Returns None if singular.
    """
    M = (M % q).astype(np.int64)
    n = M.shape[0]
    aug = np.concatenate([M, np.eye(n, dtype=np.int64)], axis=1) % q

    row = 0
    for col in range(n):
        # find pivot row
        pivot = row + np.argmax(aug[row:, col] != 0)
        if aug[pivot, col] == 0:
            return None
        if pivot != row:
            aug[[row, pivot]] = aug[[pivot, row]]

        inv_p = pow(int(aug[row, col]), -1, q)
        aug[row, :] = (aug[row, :] * inv_p) % q

        colvec = aug[:, col].copy()
        colvec[row] = 0
        if np.any(colvec):
            aug = (aug - colvec[:, None] * aug[row, :][None, :]) % q

        row += 1

    return aug[:, n:]


def precompute_sums(Cs_cols: np.ndarray, q: int) -> np.ndarray:
    """
    Cs_cols: shape (k, t). For each subset mask over t bits, compute sums over k equations.
    Returns sums[mask] as shape (k,).
    """
    k, t = Cs_cols.shape
    size = 1 << t
    sums = np.zeros((size, k), dtype=np.int64)

    for mask in range(1, size):
        lsb = mask & -mask
        j = lsb.bit_length() - 1
        prev = mask ^ lsb
        sums[mask] = (sums[prev] + Cs_cols[:, j]) % q

    return sums


def solve_one_instance(A: np.ndarray, b: np.ndarray, q: int, tries: int = 60, k: int = 4, split: int = 12):
    """
    Randomly pick N equations, invert, and solve for the unknown error bits on those equations
    using meet-in-the-middle constraints from k extra equations.
    """
    m, n = A.shape
    assert n == N

    for attempt in range(tries):
        S = random.sample(range(m), n)
        inv = inv_mod(A[S, :], q)
        if inv is None:
            continue

        bS = b[S] % q
        s0 = (inv.dot(bS)) % q

        # s = inv*(bS - eS) = s0 - inv*eS
        V = inv  # columns are inv*unit_j

        remaining = [i for i in range(m) if i not in set(S)]
        T = random.sample(remaining, k)

        # Build constraints from extra equations:
        # For each extra row r:
        #   sum_j (A_r * V_col_j) e_j  ≡  d_r  or (d_r - 1)   (mod q)
        # because e_r is either 0 or 1.
        Cs = np.empty((k, n), dtype=np.int64)
        ds = np.empty(k, dtype=np.int64)
        for r, idx in enumerate(T):
            ar = A[idx, :] % q
            ds[r] = (ar.dot(s0) - b[idx]) % q
            Cs[r, :] = (ar.dot(V)) % q

        L = list(range(split))
        R = list(range(split, n))

        sumsL = precompute_sums(Cs[:, L], q)                 # shape (2^split, k)
        table = {tuple(sumsL[i]): i for i in range(sumsL.shape[0])}

        sumsR = precompute_sums(Cs[:, R], q)                 # shape (2^(n-split), k)

        # Precompute all k-bit choices of "subtract 0 or 1" for the extra equations
        targets = []
        for choice in range(1 << k):
            sub = np.array([(choice >> r) & 1 for r in range(k)], dtype=np.int64)
            targets.append((ds - sub) % q)

        for maskR in range(sumsR.shape[0]):
            sumR = sumsR[maskR]
            for targ in targets:
                need = tuple(((targ - sumR) % q).tolist())
                maskL = table.get(need)
                if maskL is None:
                    continue

                # reconstruct e_S bits
                e = np.zeros(n, dtype=np.int64)
                for j in range(split):
                    if (maskL >> j) & 1:
                        e[j] = 1
                for j in range(n - split):
                    if (maskR >> j) & 1:
                        e[split + j] = 1

                s = (s0 - (V.dot(e) % q)) % q

                # verify on ALL equations: residual must be 0 or 1
                rvec = (b - (A.dot(s) % q)) % q
                if np.all((rvec == 0) | (rvec == 1)):
                    return s

    return None


def decode_flag_from_secret(s: np.ndarray, q: int, out_len: int) -> bytes:
    # secret digits are base-q little-endian: flag_int = sum s[i]*q^i
    flag_int = 0
    for i in range(len(s) - 1, -1, -1):
        flag_int = flag_int * q + int(s[i])
    return flag_int.to_bytes(out_len, "big")


def main():
    random.seed(1)

    # output.txt format: JSON with stringified tuples/lists
    data = json.loads(Path("output_bounded_noise.txt").read_text())
    A = np.array(ast.literal_eval(data["A"]), dtype=np.int64)
    b = np.array(ast.literal_eval(data["b"]), dtype=np.int64)

    s = solve_one_instance(A, b, Q, tries=80, k=4, split=12)
    print("S: ", s)
    if s is None:
        raise RuntimeError("Failed to recover secret. Try increasing tries or changing the random seed.")

    flag_bytes = decode_flag_from_secret(s, Q, FLAG_LEN)
    print("Flag: ", flag_bytes.decode())


if __name__ == "__main__":
    main()
