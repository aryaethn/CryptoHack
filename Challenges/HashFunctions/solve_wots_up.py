#!/usr/bin/env python3
import json
import hashlib
from Crypto.Cipher import AES

BYTE_MAX = 255
KEY_LEN = 32

def H(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def sign(priv_key, msg: bytes):
    h = H(msg)
    hb = bytearray(h)
    sig = []
    for i in range(KEY_LEN):
        s = priv_key[i]
        # chal.py: hash_iters = 255 - int_val
        for _ in range(BYTE_MAX - hb[i]):
            s = H(s)
        sig.append(s)
    return sig

def main():
    # Paths from your upload
    chal_data_path = "./data_wots_up.json"

    data = json.load(open(chal_data_path, "r"))
    pub = [bytes.fromhex(x) for x in data["public_key"]]
    sig1 = [bytes.fromhex(x) for x in data["signature"]]
    msg1 = data["message"].encode()

    iv  = bytes.fromhex(data["iv"])
    enc = bytes.fromhex(data["enc"])

    # In chal.py, signature[i] starts from priv_key[i] and hashes (255 - digest_byte) times.
    # If digest_byte == 255, then (255 - 255) == 0 => signature[i] == priv_key[i].
    h1b = bytearray(H(msg1))
    if h1b[0] != 0xFF:
        raise SystemExit(f"Exploit expects sha256(message)[0] == 0xFF, got {h1b[0]:02x}")

    # Recover priv_key[0] directly from signature[0]
    priv = [b""] * KEY_LEN
    priv[0] = sig1[0]

    # Rebuild entire private key via the hash-chain relation in __init__
    for i in range(1, KEY_LEN):
        priv[i] = H(priv[i-1])

    # (Optional) sanity: recompute pubkey and ensure it matches
    def gen_pub(priv_key):
        out = []
        for sk in priv_key:
            p = H(sk)
            for _ in range(BYTE_MAX):
                p = H(p)
            out.append(p)
        return out

    assert gen_pub(priv) == pub, "Recovered private key doesn't match public key"

    # Now sign the message used for the AES key in chal.py
    msg2 = b"Sign for flag"
    sig2 = sign(priv, msg2)

    # chal.py: aes_key = bytes([s[0] for s in signature2])
    aes_key = bytes(s[0] for s in sig2)

    pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc)
    print(pt.decode(errors="replace"))

if __name__ == "__main__":
    main()