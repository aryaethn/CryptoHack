#!/usr/bin/env python3
import json
import re
from pwn import remote, context

from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

context.log_level = "error"

HOST = "socket.cryptohack.org"
PORT = 13410


def recv_json(r, timeout=3, max_lines=200):
    """
    Read lines until we find a JSON object line.
    CryptoHack listener services often print plain-text lines before JSON.
    """
    for _ in range(max_lines):
        line = r.recvline(timeout=timeout)
        if not line:
            break
        s = line.decode(errors="ignore").strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                return json.loads(s)
            except Exception:
                pass
    raise RuntimeError("Failed to receive JSON response (timeout / unexpected output).")


def recv_banner_and_extract_jsons(r):
    """
    Parse the initial banner. It contains multiple JSON objects on separate lines.
    We skip text lines and collect the three blobs we need.
    """
    material = None
    file_upload = None
    recovered = None

    for _ in range(600):
        line = r.recvline(timeout=2)
        if not line:
            break
        s = line.decode(errors="ignore").strip()
        if not (s.startswith("{") and s.endswith("}")):
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue

        if "master_key_enc" in obj and "share_key_enc" in obj and "share_key_pub" in obj:
            material = obj
        elif "node_key_enc" in obj and "file_enc" in obj:
            file_upload = obj
        elif "share_key" in obj:
            recovered = obj

        if material and file_upload and recovered:
            return material, file_upload, recovered

    raise RuntimeError("Could not extract required JSON blobs from banner.")


def format_number(num: int) -> bytes:
    nb = long_to_bytes(num)
    return long_to_bytes(len(nb), 2) + nb


def choose_injection_block(plain_padded: bytes, u_start: int, u_len: int) -> tuple[int, int]:
    """
    Find a block index b such that blocks b and b+1 lie fully within u bytes,
    and don't touch the first 16 bytes of u (keep the top stable).
    """
    num_blocks = len(plain_padded) // 16
    for b in range(num_blocks - 1):
        start = 16 * b
        if start >= u_start and (start + 32) <= (u_start + u_len):
            start_in_u = start - u_start
            if start_in_u >= 16:
                return b, start_in_u
    raise RuntimeError("Could not find a safe aligned 2-block window inside u.")


def recover_uprime_from_prefix(prefix_bytes: bytes, p: int, u_len: int,
                               known_u_bytes: bytes, start_in_u: int, inj_len: int = 32):
    """
    Client returns long_to_bytes(m')[:-16], so we know m' up to last 128 bits.
    m' = u' * p. Recover u' by dividing two boundary candidates and scoring.
    """
    prefix_int = bytes_to_long(prefix_bytes) << 128
    candidates = []
    for cand in [prefix_int // p, (prefix_int + (1 << 128) - 1) // p]:
        ub = long_to_bytes(cand, u_len)
        score = 0
        for i in range(u_len):
            if start_in_u <= i < start_in_u + inj_len:
                continue
            if ub[i] == known_u_bytes[i]:
                score += 1
        candidates.append((score, cand, ub))
    candidates.sort(reverse=True, key=lambda x: x[0])
    return candidates[0][1], candidates[0][2]


def main():
    r = remote(HOST, PORT)

    material, file_upload, recovered = recv_banner_and_extract_jsons(r)

    master_key_enc = bytes.fromhex(material["master_key_enc"])
    share_key_enc  = bytes.fromhex(material["share_key_enc"])
    n, e = material["share_key_pub"]

    node_key_enc = bytes.fromhex(file_upload["node_key_enc"])
    file_enc = bytes.fromhex(file_upload["file_enc"])

    leaked_n, leaked_e, leaked_p = recovered["share_key"]
    assert leaked_n == n and leaked_e == e
    p = leaked_p
    q = n // p
    d = inverse(e, (p - 1) * (q - 1))

    # CRT convention in this challenge: u = p^{-1} mod q
    u = inverse(p, q)
    u_bytes = long_to_bytes(u)
    u_len = len(u_bytes)

    # reconstruct plaintext layout of the RSA blob to locate u offset
    enc_p = format_number(p)
    enc_q = format_number(q)
    enc_d = format_number(d)
    enc_u = format_number(u)
    rsa_blob_plain = enc_p + enc_q + enc_d + enc_u

    pad_len = 16 - (len(rsa_blob_plain) % 16)
    rsa_blob_padded = rsa_blob_plain + bytes([pad_len]) * pad_len
    if len(rsa_blob_padded) != len(share_key_enc):
        raise RuntimeError(
            "Reconstructed RSA blob length doesn't match share_key_enc. "
            "Likely u convention mismatch."
        )

    u_start = len(enc_p) + len(enc_q) + len(enc_d) + 2  # skip u length prefix
    b, start_in_u = choose_injection_block(rsa_blob_padded, u_start, u_len)

    # splice ECB blocks
    mod = bytearray(share_key_enc)
    mod[16*b : 16*b+16] = node_key_enc
    mod[16*(b+1) : 16*(b+2)] = node_key_enc

    # special RSA plaintext: m = p*u  => m mod p = 0, m mod q = 1
    m = p * u
    SID_enc_int = pow(m, e, n)
    SID_enc = long_to_bytes(SID_enc_int, 256)

    # --- enter LOGIN state ---
    r.sendline(json.dumps({"action": "wait_login"}).encode())
    resp = recv_json(r)
    # resp is {"auth_key_hashed": ...}
    # (there may have been a preceding text line; recv_json skips it)

    # --- trigger login_step2 oracle ---
    payload = {
        "action": "send_challenge",
        "SID_enc": SID_enc.hex(),
        "share_key_enc": bytes(mod).hex(),
        "master_key_enc": master_key_enc.hex(),
    }
    r.sendline(json.dumps(payload).encode())
    resp = recv_json(r)

    if "error" in resp:
        raise RuntimeError(f"Server error: {resp['error']}")
    if "SID" not in resp:
        raise RuntimeError(f"Unexpected response (no SID): {resp}")

    SID_prefix = bytes.fromhex(resp["SID"])

    # recover u' then extract node_key
    _, u_prime_bytes = recover_uprime_from_prefix(
        SID_prefix, p, u_len, u_bytes, start_in_u, inj_len=32
    )
    recovered_32 = u_prime_bytes[start_in_u : start_in_u + 32]
    node_key = recovered_32[:16]

    pt = unpad(AES.new(node_key, AES.MODE_ECB).decrypt(file_enc), 16)

    print(pt.decode(errors="ignore"))
    m = re.search(rb"crypto\{[^}]+\}", pt)
    if m:
        print("\nFLAG:", m.group(0).decode())

    r.close()


if __name__ == "__main__":
    main()