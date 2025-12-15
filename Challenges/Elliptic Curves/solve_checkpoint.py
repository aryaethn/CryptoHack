#!/usr/bin/env sage -python3
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

import socket
import json
import re
from itertools import product


# ============================================================
#  P-256 curve params
# ============================================================

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


# ============================================================
#  Network helpers (CryptoHack JSON line protocol)
# ============================================================

HOST = "socket.cryptohack.org"
PORT = 13419

def make_socket():
    s = socket.create_connection((HOST, PORT))
    s.settimeout(5.0)
    return s

def recv_until(sock, token=b"\n", max_bytes=1 << 20):
    data = b""
    while token not in data and len(data) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def send_json(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b"\n")

def recv_json(sock):
    line = recv_until(sock, b"\n")
    if not line:
        raise TimeoutError("No JSON line received")
    line = line.split(b"\n")[0]
    return json.loads(line.decode())


def read_banner(sock):
    """
    Parse the initial plaintext banner:

      client->server : Point(x=..., y=...)
      server->client : Point(x=..., y=...)
      server->client : <hex ciphertext>
    """
    buf = b""
    for _ in range(80):
        chunk = recv_until(sock, b"\n")
        if not chunk:
            break
        buf += chunk
        text = buf.decode(errors="ignore")

        cp = re.search(r"client->server : Point\(x=(\d+), y=(\d+)\)", text)
        sp = re.search(r"server->client : Point\(x=(\d+), y=(\d+)\)", text)
        cts = re.findall(r"server->client : ([0-9a-f]+)", text)

        if cp and sp and cts:
            client_pub = (int(cp.group(1)), int(cp.group(2)))
            server_pub = (int(sp.group(1)), int(sp.group(2)))
            flag_ct = bytes.fromhex(cts[-1])  # iv||ct of the FLAG
            return client_pub, server_pub, flag_ct

    raise ValueError("Failed to parse banner:\n" + buf.decode(errors="ignore"))


# ============================================================
#  Crypto helpers (same logic as challenge)
# ============================================================

def derive_key_from_x(x_int):
    """
    Key derivation used by the challenge:
      key = sha256(str(shared_x).encode())[:16]
    """
    return sha256(str(int(x_int)).encode()).digest()[:16]


def decrypt_cbc(key, iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pt  # caller decides to unpad / search strings


# ============================================================
#  Subgroup hunting: match the working logic you gave
# ============================================================

order_list = []
Q_list = []

def find_curves_with_small_subgroup(p, a, max_order, target_points=17):
    """
    Exact logic from your working snippet:

      - Enumerate b = 1,2,...
      - Skip singular curves
      - For each curve, sample random points R
      - Factor point order n = ord(R)
      - Take prime factors f in [2^10, 2^20), f <= max_order
      - Ensure we only use each f once
      - Construct P = (n/f)*R with exact order f
      - Yield (f, P, b)
    """
    orders_found = set()
    b_val = 0

    while b_val < 22:
        b_val += 1
        if b_val == p:
            break

        # Skip singular curve
        if (4 * a**3 + 27 * b_val**2) % p == 0:
            continue

        E = EllipticCurve(GF(p), [a, b_val])

        for _ in range(100):
            R = E.random_point()
            n = R.order()

            # factor point order (not full curve order)
            facs = n.factor(limit=2**20)
            print("Factors on b_val = ", b_val, " for n = ", n, " are: ", facs)

            for f, e in facs:
                f_int = int(f)
                if f in orders_found:
                    continue
                # if f_int > max_order:
                #     break
                if f_int in range(2**10, 2**20):
                    # Create a point with order f
                    P = (n // f) * R
                    assert P.order() == f
                    print(f"{(b_val, P, f_int) = }")
                    Q_list.append((b_val, P, f_int))
                    orders_found.add(f)
                    yield (f_int, P, b_val)
                    # if len(Q_list) >= target_points:
                    #     return


# ============================================================
#  ECDH oracle logic (same as your working code)
# ============================================================

def get_test_cipher_for_Q(sock, Qx, Qy):
    """
    For a given attack point Q, ask the remote service for
    the test ciphertext encrypted under sha256(shared_x)[:16].
    """
    req = {
        "option": "start_key_exchange",
        "ciphersuite": "ECDHE_P256_WITH_AES_128",
        "Qx": hex(int(Qx))[2:],
        "Qy": hex(int(Qy))[2:],
    }
    send_json(sock, req)
    resp = recv_json(sock)
    msg = resp.get("msg", "")
    if "successfully" not in msg:
        return None, None

    req2 = {"option": "get_test_message"}
    send_json(sock, req2)
    resp2 = recv_json(sock)
    hex_ct = resp2["msg"]
    iv = bytes.fromhex(hex_ct[:32])
    ct = bytes.fromhex(hex_ct[32:])
    return iv, ct


def recover_residue_for_subgroup(sock, E, Q, order_Q):
    """
    For a subgroup generated by Q of order order_Q:
      - Ask server to encrypt SERVER_TEST_MESSAGE under shared_x
      - Try all multiples k*Q, derive key, decrypt, look for substring
      - Once found, return residue k (i.e., s ≡ k mod order_Q)

    This matches the logic in your working code, except we just
    use k instead of computing discrete_log(i, Q) (they are congruent mod order).
    """
    iv2, ct2 = get_test_cipher_for_Q(sock, Q[0], Q[1])
    if iv2 is None:
        return None

    # try all multiples
    for k in range(1, order_Q):
        Pk = k * Q
        x = Pk[0]
        key = derive_key_from_x(x)
        pt = decrypt_cbc(key, iv2, ct2)
        if b"SERVER_TEST_MESSAGE" in pt:
            # In the original code, they did: discrete_log(i, Q)
            # Here i = k*Q, discrete_log(i,Q) == k mod order_Q.
            return k

    return None


# ============================================================
#  Main solve logic: CRT + sign ambiguity like your code
# ============================================================

def main():
    max_order = 2**17

    # 1) Offline: find some small-order points on twist curves
    print("[*] Hunting small-subgroup points locally...")
    for order, P, b_val in find_curves_with_small_subgroup(p, a, max_order, target_points=17):
        order_list.append(order)
        # Q_list already filled

    print(f"[*] Found {len(Q_list)} subgroup points")
    # Q_list: list of (b, P, order)

    # 2) Connect to CryptoHack, read banner (Q_server, P_server, FLAG ciphertext)
    sock = make_socket()
    client_pub, server_pub, flag_blob = read_banner(sock)
    print(f"[*] client_pub = {client_pub}")
    print(f"[*] server_pub = {server_pub}")
    print(f"[*] flag_cipher len = {len(flag_blob)}")

    iv_flag, ct_flag = flag_blob[:16], flag_blob[16:]

    # 3) For each (b, P, order), recover residue for s mod order
    remainders = []
    moduli = []

    index = 0
    for b_val, P, order_Q in Q_list:
        index += 1
        print(f"[*] Using subgroup #{index} with b = {b_val}, order = {order_Q}")

        E_twist = EllipticCurve(GF(p), [a, b_val])
        Q = E_twist(P[0], P[1])

        residue = recover_residue_for_subgroup(sock, E_twist, Q, order_Q)
        if residue is None:
            print(f"[!] Failed to recover residue for order {order_Q}, skipping")
            continue

        print(f"[+] Index {index}: s ≡ {residue} (mod {order_Q})")
        remainders.append(residue)
        moduli.append(order_Q)

    print("[*] residues =", remainders)
    print("[*] moduli   =", moduli)
    assert len(remainders) == len(moduli)

    # 4) Now do CRT with sign ambiguity, as in your working code
    print("[*] Starting CRT with sign ambiguity search...")

    # Real P-256 curve & Q_server for final flag decryption
    E_real = EllipticCurve(GF(p), [a, b])
    Q_real = E_real(client_pub[0], client_pub[1])

    # All ± combinations on residues
    sign_remainders = []
    for signs in product([1, -1], repeat=len(remainders)):
        signed = [(sign * val) % m for sign, val, m in zip(signs, remainders, moduli)]
        sign_remainders.append(signed)

    # Search for a candidate d with <=256 bits that decrypts flag to crypto{...}
    for r_vals in sign_remainders:
        d_mod = crt([Integer(v) for v in r_vals],
                    [Integer(m) for m in moduli])
        d = int(d_mod)

        if d.bit_length() > 256:
            continue

        shared_x = (d * Q_real)[0]
        key = derive_key_from_x(shared_x)
        pt = decrypt_cbc(key, iv_flag, ct_flag)

        if b"crypto{" in pt:
            print(f"[+] Found d = {d}")
            print(pt)
            break
    else:
        print("[!] No valid d found; try collecting more residues or adjusting search.")


if __name__ == "__main__":
    main()