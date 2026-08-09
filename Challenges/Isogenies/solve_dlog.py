import re
import sys
from sage.all import GF, EllipticCurve, Integer

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad


# ----------------------------
# Parsing helpers
# ----------------------------

POINT_RE = re.compile(r"\(\s*([0-9]+)\*i\s*\+\s*([0-9]+)\s*:\s*([0-9]+)\*i\s*\+\s*([0-9]+)\s*:\s*1\s*\)")
IV_RE = re.compile(r"iv\s*=\s*'([0-9a-fA-F]+)'")
CT_RE = re.compile(r"ct\s*=\s*'([0-9a-fA-F]+)'")


def parse_point(line, E, i):
    """
    Parse a line like:
      P = (A*i + B : C*i + D : 1)
    and return the Sage point E(x,y).
    """
    m = POINT_RE.search(line)
    if not m:
        raise ValueError(f"Could not parse point line:\n{line}")

    ax_i = Integer(m.group(1))
    ax_c = Integer(m.group(2))
    ay_i = Integer(m.group(3))
    ay_c = Integer(m.group(4))

    x = ax_i * i + ax_c
    y = ay_i * i + ay_c
    return E(x, y)


def parse_output(path, E, i):
    P = Q = R = S = None
    iv_hex = ct_hex = None

    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith("P ="):
            P = parse_point(line, E, i)
        elif line_stripped.startswith("Q ="):
            Q = parse_point(line, E, i)
        elif line_stripped.startswith("R ="):
            R = parse_point(line, E, i)
        elif line_stripped.startswith("S ="):
            S = parse_point(line, E, i)

        m_iv = IV_RE.search(line)
        if m_iv:
            iv_hex = m_iv.group(1)

        m_ct = CT_RE.search(line)
        if m_ct:
            ct_hex = m_ct.group(1)

    if None in (P, Q, R, S, iv_hex, ct_hex):
        raise ValueError("Failed to parse some of P,Q,R,S,iv,ct from output file.")

    return P, Q, R, S, iv_hex, ct_hex


# ----------------------------
# Group / pairing helpers
# ----------------------------

def power_of_two_order(elem, max_bits=200):
    """
    If elem has order 2^k (a pure power of two), return k.
    We detect the smallest k such that elem^(2^k) == 1 by repeated squaring.
    """
    t = elem
    k = 0
    while t != 1:
        t = t * t   # square => exponent doubles
        k += 1
        if k > max_bits:
            raise ValueError("Element did not reach 1 within max_bits squarings; not a 2-power order?")
    return k


def pow2_dlog_bitlift(g, h, k, verbose=True, print_every=16):
    """
    Solve h = g^x in a cyclic group where ord(g) = 2^k.
    Returns x modulo 2^k.

    Method: recover x bit-by-bit using the unique order-2 element test.

    At step j (recovering bit j):
      Let m = k - j be remaining exponent bits in current subgroup.
      The element u = g_cur^(2^(m-1)) has order 2.
      For h_cur = g_cur^x_rem:
        h_cur^(2^(m-1)) is 1 if x_rem even, u if x_rem odd.
    """
    x = Integer(0)
    g_cur = g
    h_cur = h

    if verbose:
        print(f"[dlog] Solving h = g^x with ord(g)=2^{k} ...")

    for j in range(k):
        m = k - j  # remaining bits in current subgroup

        # Compute t = h_cur^(2^(m-1)) by repeated squaring (m-1 times)
        t = h_cur
        for _ in range(m - 1):
            t = t * t

        if t == 1:
            bit = 0
        else:
            # Compute u = g_cur^(2^(m-1)) (the unique order-2 element)
            u = g_cur
            for _ in range(m - 1):
                u = u * u

            if t != u:
                raise ValueError("Unexpected value when extracting parity bit; group assumptions violated?")
            bit = 1
            h_cur = h_cur / g_cur  # remove this bit (makes exponent even)

        x += Integer(bit) * (Integer(1) << j)

        # Move to subgroup of half order: base squares
        g_cur = g_cur * g_cur

        if verbose and (j % print_every == 0 or j == k - 1):
            # show partial progress
            shown_bits = j + 1
            print(f"  - recovered bit {j} = {bit}   (x mod 2^{shown_bits} = {int(x)})")

    if verbose:
        print(f"[dlog] Done. x mod 2^{k} = {int(x)}")
    return x


def lift_candidates(x_mod_2k, k, target_bits):
    """
    Lift a value known modulo 2^k up to modulo 2^target_bits.
    If k == target_bits: only one candidate.
    If k == target_bits-1: exactly two candidates: x and x+2^k.
    More generally, returns all 2^(target_bits-k) lifts (but we only need the common case).
    """
    if k > target_bits:
        raise ValueError("k cannot exceed target_bits")
    step = Integer(1) << k
    count = Integer(1) << (target_bits - k)
    return [x_mod_2k + t * step for t in range(int(count))]


def find_ab(P, Q, R, a_cands, b_cands):
    for a in a_cands:
        for b in b_cands:
            if a * P + b * Q == R:
                return a, b
    raise ValueError("No (a,b) candidates matched R. Something is wrong.")


# ----------------------------
# Main solve
# ----------------------------

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output_dlog.txt"

    # Same parameters as source.sage
    p = Integer(2) ** 127 - 1
    N = p + 1  # = 2^127

    print("[*] Building field F = GF(p^2) with i^2+1=0 ...")
    F = GF(p**2, name="i", modulus=[1, 0, 1])
    i = F.gen()

    print("[*] Building curve E: y^2 = x^3 + x over F ...")
    E = EllipticCurve(F, [1, 0])

    print(f"[*] Parsing {path} ...")
    P, Q, R, S, iv_hex, ct_hex = parse_output(path, E, i)

    print("[*] Parsed points:")
    print("    P =", P)
    print("    Q =", Q)
    print("    R =", R)
    print("    S =", S)
    print("    iv =", iv_hex)
    print("    ct =", ct_hex[:48] + "..." if len(ct_hex) > 48 else ct_hex)

    n = N  # pairing torsion size 2^127
    print(f"[*] Using n = p+1 = {n} (= 2^127) for Weil pairing.")

    # Pairing base
    print("[*] Computing g = e_n(P, Q) ...")
    g = P.weil_pairing(Q, n)

    k = power_of_two_order(g, max_bits=200)
    print(f"[*] ord(g) = 2^{k} (so pairing reveals exponents mod 2^{k}).")

    # Extract exponents modulo 2^k
    print("\n[*] Recovering a from e(R, Q) = g^a ...")
    ha = R.weil_pairing(Q, n)
    a0 = pow2_dlog_bitlift(g, ha, k, verbose=True)

    print("\n[*] Recovering b from e(P, R) = g^b ...")
    hb = P.weil_pairing(R, n)
    b0 = pow2_dlog_bitlift(g, hb, k, verbose=True)

    print("\n[*] Recovering c from e(S, Q) = g^c ...")
    hc = S.weil_pairing(Q, n)
    c0 = pow2_dlog_bitlift(g, hc, k, verbose=True)

    print("\n[*] Recovering d from e(P, S) = g^d ...")
    hd = P.weil_pairing(S, n)
    d0 = pow2_dlog_bitlift(g, hd, k, verbose=True)

    # Lift to modulo 2^127 if needed
    target_bits = 127
    print("\n[*] Lifting candidates up to mod 2^127 and verifying against R,S ...")

    a_cands = lift_candidates(a0, k, target_bits)
    b_cands = lift_candidates(b0, k, target_bits)
    c_cands = lift_candidates(c0, k, target_bits)
    d_cands = lift_candidates(d0, k, target_bits)

    print(f"    a candidates: {len(a_cands)}")
    print(f"    b candidates: {len(b_cands)}")
    print(f"    c candidates: {len(c_cands)}")
    print(f"    d candidates: {len(d_cands)}")

    a, b = find_ab(P, Q, R, a_cands, b_cands)
    c, d = find_ab(P, Q, S, c_cands, d_cands)

    # Reduce mod N (safe / canonical)
    a %= N
    b %= N
    c %= N
    d %= N

    print("\n[+] Found coefficients (mod 2^127):")
    print("    a =", int(a))
    print("    b =", int(b))
    print("    c =", int(c))
    print("    d =", int(d))

    # Decrypt flag
    print("\n[*] Decrypting ciphertext using the same key derivation as source.sage ...")
    data_abcd = str(int(a)) + str(int(b)) + str(int(c)) + str(int(d))
    key = SHA256.new(data=data_abcd.encode()).digest()[:128]  # (slice is weird, but matches source)
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except ValueError:
        # If padding fails, show raw plaintext to debug
        print("[!] Unpad failed. Raw plaintext bytes:")
        print(pt)
        raise

    print("[+] Plaintext:")
    print(pt.decode(errors="replace"))

    # Sanity checks
    if not pt.startswith(b"crypto{"):
        print("[!] Warning: plaintext does not start with crypto{ ... something may be off.")
    else:
        print("[+] Looks like a valid flag.")

if __name__ == "__main__":
    main()
