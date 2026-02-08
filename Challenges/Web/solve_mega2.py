#!/usr/bin/env python3
import json
import math
import time
from fractions import Fraction

from pwn import remote
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long, getRandomRange
from Crypto.Util.Padding import unpad

HOST = "socket.cryptohack.org"
PORT = 13409

CHOP_BYTES = 16
X = 1 << (8 * CHOP_BYTES)  # 2^128


# ---------------------------
# Robust JSON extraction from mixed text stream
# ---------------------------
def extract_first_json_object(buf: bytes):
    """
    Return first balanced {...} JSON object found in buf using brace counting.
    Handles quoted strings and escapes so braces inside strings don't break parsing.
    Returns bytes or None.
    """
    start = buf.find(b"{")
    if start == -1:
        return None

    depth = 0
    in_str = False
    esc = False

    for i in range(start, len(buf)):
        c = buf[i]

        if in_str:
            if esc:
                esc = False
            elif c == ord("\\"):
                esc = True
            elif c == ord('"'):
                in_str = False
            continue

        if c == ord('"'):
            in_str = True
            continue
        if c == ord("{"):
            depth += 1
        elif c == ord("}"):
            depth -= 1
            if depth == 0:
                return buf[start:i+1]
    return None


def recv_json_object(io, timeout=8.0, max_bytes=200_000):
    """
    Read from socket until we can extract+parse one JSON object.
    Skips any human text lines that listener prints.
    """
    buf = b""
    t0 = time.time()

    while time.time() - t0 < timeout and len(buf) < max_bytes:
        chunk = io.recv(timeout=0.3)
        if chunk:
            buf += chunk
            obj_bytes = extract_first_json_object(buf)
            if obj_bytes:
                try:
                    return json.loads(obj_bytes.decode())
                except Exception:
                    # Keep reading: could have grabbed something that's not the JSON we want
                    # (rare, but safe).
                    pass

    tail = buf[-500:].decode(errors="replace")
    raise RuntimeError(f"Could not parse JSON from stream. Tail:\n{tail}")


def recv_material(io):
    # The server banner contains the material JSON, but mixed with text.
    return recv_json_object(io, timeout=10.0)


def send_action(io, obj):
    io.sendline(json.dumps(obj).encode())
    # Response may be preceded by human text like "Login attempt from Alice:"
    return recv_json_object(io, timeout=6.0)


# ---------------------------
# ECB cut-and-paste (corrupt q only)
# ---------------------------
def make_faulty_share_key_enc(share_key_enc_hex):
    """
    Based on the plaintext layout in the challenge:
      [2|p][2|q][2|d][2|u] with p,q,u ~128 bytes and d~256 bytes.
    For RSA-2048 this is 656 bytes padded => 41 blocks of 16.

    q bytes occupy blocks 9..15 fully (safe to corrupt) while
    block 8 holds the q length field and block 16 starts d length field (don't touch).
    """
    ct = bytes.fromhex(share_key_enc_hex)
    if len(ct) % 16 != 0:
        raise RuntimeError("share_key_enc not block-aligned")

    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    if len(blocks) != 41:
        # If this ever differs, we can adapt — but CryptoHack keeps it stable here.
        raise RuntimeError(f"Unexpected share_key_enc blocks: {len(blocks)} (expected 41)")

    blocks_faulty = blocks[:]

    # Replace q-middle blocks 9..15 (7 blocks) with blocks 33..39
    src = 33
    for j, bi in enumerate(range(9, 16)):
        blocks_faulty[bi] = blocks[src + j]

    return b"".join(blocks_faulty).hex()


# ---------------------------
# Tiny pure-Python LLL (dimension 5 only, so fast enough)
# ---------------------------
def dot(u, v):
    return sum(Fraction(a) * Fraction(b) for a, b in zip(u, v))

def vec_sub(u, v):
    return [a - b for a, b in zip(u, v)]

def vec_mul_scalar(u, s):
    return [a * s for a in u]

def round_fraction(x: Fraction) -> int:
    if x >= 0:
        return int(x + Fraction(1, 2))
    return -int((-x) + Fraction(1, 2))

def gram_schmidt(B):
    n = len(B)
    m = len(B[0])
    Bstar = [[Fraction(0) for _ in range(m)] for _ in range(n)]
    mu = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    norm = [Fraction(0) for _ in range(n)]

    for i in range(n):
        v = [Fraction(x) for x in B[i]]
        for j in range(i):
            if norm[j] == 0:
                mu[i][j] = Fraction(0)
                continue
            mu[i][j] = dot(B[i], Bstar[j]) / norm[j]
            v = vec_sub(v, vec_mul_scalar(Bstar[j], mu[i][j]))
        Bstar[i] = v
        norm[i] = dot(v, v)
    return mu, Bstar, norm

def lll_reduction(B_int, delta=Fraction(3, 4)):
    B = [list(map(int, row)) for row in B_int]
    n = len(B)
    k = 1
    while k < n:
        mu, Bstar, norm = gram_schmidt(B)

        # size reduce
        for j in range(k - 1, -1, -1):
            q = round_fraction(mu[k][j])
            if q != 0:
                B[k] = vec_sub(B[k], vec_mul_scalar(B[j], q))

        mu, Bstar, norm = gram_schmidt(B)

        # Lovasz
        if norm[k] >= (delta - mu[k][k-1] * mu[k][k-1]) * norm[k-1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            k = max(k - 1, 1)
    return B

def lll_factor_from_acd(n, A_list):
    """
    A_i = m - (P<<128) = p*k_i + r_i, with r_i < 2^128
    Lattice basis in Z^(t+1):
      [ X,  A1, A2, ..., At ]
      [ 0,  n,  0,  ... 0  ]
      [ 0,  0,  n,  ... 0  ]
      ...
    LLL then gcd with n.
    """
    t = len(A_list)
    basis = []
    basis.append([X] + [int(A) for A in A_list])
    for i in range(1, t + 1):
        row = [0] * (t + 1)
        row[i] = int(n)
        basis.append(row)

    red = lll_reduction(basis)

    for row in red:
        for v in row:
            g = math.gcd(abs(int(v)), int(n))
            if 1 < g < n:
                return g
    return None


# ---------------------------
# Flag decryption
# ---------------------------
def try_decrypt_flag(ct_flag_hex, p, q):
    ct = bytes.fromhex(ct_flag_hex)
    for a, b in [(p, q), (q, p)]:
        key = SHA256.new(long_to_bytes(a) + long_to_bytes(b)).digest()
        pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
        try:
            msg = unpad(pt, 16)
        except ValueError:
            continue
        if b"crypto{" in msg:
            return msg.decode(errors="replace")
    return None


def one_session():
    io = remote(HOST, PORT)

    material = recv_material(io)
    n, e = material["share_key_pub"]
    master_key_enc_hex = material["master_key_enc"]
    share_key_enc_hex = material["share_key_enc"]

    faulty_share_key_enc_hex = make_faulty_share_key_enc(share_key_enc_hex)

    resp = send_action(io, {"action": "get_encrypted_flag"})
    ct_flag_hex = resp["encrypted_flag"]

    k = (int(n).bit_length() + 7) // 8
    out_len = k - CHOP_BYTES

    A_list = []

    for _ in range(4):
        _ = send_action(io, {"action": "wait_login"})

        # choose m high-bit set to stabilize byte-length
        low = 1 << (8 * k - 1)
        if low >= n:
            low = 2
        m = int(getRandomRange(low, int(n) - 1))

        c = pow(m, int(e), int(n))

        resp2 = send_action(io, {
            "action": "send_challenge",
            "SID_enc": long_to_bytes(c).hex(),
            "share_key_enc": faulty_share_key_enc_hex,
            "master_key_enc": master_key_enc_hex,
        })

        if "error" in resp2:
            raise RuntimeError(f"Login failed: {resp2}")

        sid_hi = bytes.fromhex(resp2["SID"])
        # server uses long_to_bytes(), so left-pad chopped output to fixed length
        sid_hi = sid_hi.rjust(out_len, b"\x00")

        P = bytes_to_long(sid_hi)
        A = int(m) - (int(P) << (8 * CHOP_BYTES))
        A_list.append(A)

    io.close()

    factor = lll_factor_from_acd(int(n), A_list)
    if not factor:
        return None

    p = factor
    q = int(n) // p
    return try_decrypt_flag(ct_flag_hex, p, q)


def main():
    # LLL can be finicky; retry fresh sessions (fresh RSA each time).
    for attempt in range(1, 15):
        try:
            flag = one_session()
            if flag:
                print(flag)
                return
            print(f"[!] Attempt {attempt}: no factor found, retrying...")
        except Exception as ex:
            print(f"[!] Attempt {attempt} crashed: {ex}. Retrying...")

    print("[!] Gave up after several attempts.")


if __name__ == "__main__":
    main()