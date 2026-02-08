import numpy as np

PK_PATH = "public_key_nativity.txt"
CT_PATH = "ciphertexts_nativity.txt"

def gf2_nullspace_one_vector(M):
    """
    Find a nonzero x such that M @ x = 0 over GF(2).
    Here M is (rows x nvars) with entries 0/1 (uint8).
    We return one basis vector as a bitmask integer.
    """
    rows, nvars = M.shape
    # pack each row into a Python int bitmask
    r = []
    for i in range(rows):
        mask = 0
        row = M[i]
        for j in range(nvars):
            mask |= (int(row[j]) & 1) << j
        r.append(mask)

    piv_row_for_col = [-1] * nvars
    row_i = 0

    # Gauss-Jordan over GF(2)
    for col in range(nvars):
        pivot = None
        for k in range(row_i, rows):
            if (r[k] >> col) & 1:
                pivot = k
                break
        if pivot is None:
            continue
        r[row_i], r[pivot] = r[pivot], r[row_i]
        piv_row_for_col[col] = row_i

        for k in range(rows):
            if k != row_i and ((r[k] >> col) & 1):
                r[k] ^= r[row_i]

        row_i += 1
        if row_i == rows:
            break

    free_cols = [c for c in range(nvars) if piv_row_for_col[c] == -1]
    if not free_cols:
        raise ValueError("No nullspace found (unexpected for this challenge).")

    # Build one nullspace vector by setting one free var = 1
    free = free_cols[0]
    vec = 1 << free

    # For each pivot row, set pivot var to satisfy the equation
    # r[prow] · x = 0, with pivot bit present.
    row_to_pivotcol = {piv_row_for_col[c]: c for c in range(nvars) if piv_row_for_col[c] != -1}
    for prow, pcol in row_to_pivotcol.items():
        parity = (bin(r[prow] & vec).count("1") & 1)
        if parity:
            vec |= 1 << pcol

    return vec

def main():
    pk = np.loadtxt(PK_PATH, dtype=np.uint16)      # (65, 512)
    cts = np.loadtxt(CT_PATH, dtype=np.uint16)     # (num_bits, 65)

    # Solve pk^T x = 0 over GF(2)
    M = (pk.T & 1).astype(np.uint8)                # (512, 65)
    x_mask = gf2_nullspace_one_vector(M)
    x = np.array([(x_mask >> j) & 1 for j in range(pk.shape[0])], dtype=np.uint8)

    # Recover msg bits: msg = <x, c> mod 2  (since x_last = 1 here)
    bits = ((cts & 1).astype(np.uint8) @ x) & 1

    bitstr = "".join(str(int(b)) for b in bits)
    flag_bytes = bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8))
    print(flag_bytes.decode())

if __name__ == "__main__":
    main()
