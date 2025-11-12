# SageMath script
# Usage: sage solve_flag.sage flag.enc
import sys
from sage.all import *

# --- constants from the challenge ---
E = 31337
N = 50
FLAG_LEN_BYTES = 34
FLAG_LEN_BITS  = FLAG_LEN_BYTES * 8

# --- helpers matching the challenge's bit packing ---
def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            if i + j < len(bits):
                b = (b << 1) | int(bits[i + j])
        out.append(b)
    return bytes(out)

def matrix_to_msg_bits_col_major(M):
    # M[i][j] = msg[i + j*N] in the challenge
    # So iterate columns then rows to reconstruct msg[]
    bits = []
    for j in range(N):          # columns
        for i in range(N):      # rows
            bits.append(int(M[i, j]))
    return bits

def decode_flag_from_matrix(M):
    bits = matrix_to_msg_bits_col_major(M)
    flag_bits = bits[:FLAG_LEN_BITS]
    return bits_to_bytes(flag_bits)

def load_cipher_matrix(path):
    with open(path, 'r') as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    if len(lines) != N or any(len(ln) != N for ln in lines):
        raise ValueError("Input must be a 50x50 matrix of 0/1 (no spaces).")
    rows = [[int(c) for c in ln] for ln in lines]
    return Matrix(GF(2), rows)

def looks_like_flag(b):
    # minimal sanity checks for CryptoHack-style flags
    try:
        s = b.decode('ascii', errors='ignore')
    except:
        return False
    return s.startswith('crypto{') and s.endswith('}') and len(b) == FLAG_LEN_BYTES

def recover_M_from_C(C):
    # Compute order of C
    mC = C.multiplicative_order()
    # Try the straightforward case first: invert E modulo mC
    if gcd(E, mC) == 1:
        invE = inverse_mod(E, mC)
        M0 = C**Integer(invE)
        yield M0  # unique E-th root in <C>
        # Very rare robustness: if E | ord(M) and E^2 | ord(M), we can have more roots.
        # In that subcase, ord(C) is divisible by E, so we can enumerate Z = C^(mC/E).
        if mC % E == 0:
            Z = C**Integer(mC // E)    # order E and commutes with C
            R = Matrix(GF(2), identity_matrix(GF(2), N))
            for r in range(E):
                yield M0 * R           # R = Z^r; start with r=0 (already yielded)
                R = R * Z
        return

    # If gcd(E, mC) != 1, we’re in the (very) rare case where E shares factors with ord(C).
    # Then we still might enumerate the commuting E-th roots via Z if E | mC.
    if mC % E == 0:
        # Find one particular E-th root first by solving E*t + mC*u = 1 if possible modulo mC/E
        # but a simpler practical path: pick any t with (E*t) % mC == 1 if gcd(E, mC) == 1 on the reduced group.
        # If that fails, just set a fallback root to identity and enumerate via Z.
        try:
            invE = inverse_mod(E, mC // E)  # heuristic; may or may not help
            M0 = C**Integer(invE)
        except Exception:
            M0 = Matrix(GF(2), identity_matrix(GF(2), N))
        Z = C**Integer(mC // E)  # order E
        R = Matrix(GF(2), identity_matrix(GF(2), N))
        for r in range(E):
            yield M0 * R
            R = R * Z
    else:
        raise RuntimeError("Could not invert exponent and no enumeration path available.")

def main():
    if len(sys.argv) != 2:
        print("Usage: sage solve_flag.sage flag.enc")
        sys.exit(1)

    C = load_cipher_matrix(sys.argv[1])

    tried = 0
    for M in recover_M_from_C(C):
        tried += 1
        flag = decode_flag_from_matrix(M)
        if looks_like_flag(flag):
            print(flag.decode('ascii'))
            return

    # If none matched the pattern, still print the best-looking candidate(s) for manual inspection
    if tried == 0:
        print("No roots tested. Something is off with the input file or group order.")
        return

    print("No candidate produced a well-formed flag. Dumping first candidate bytes for debugging:")
    # Re-run one candidate to show bytes
    M = next(recover_M_from_C(C))
    flag = decode_flag_from_matrix(M)
    print(flag)  # raw bytes

if __name__ == "__main__":
    main()