#!/usr/bin/env python3
import json, hashlib
from Crypto.Cipher import AES

BYTE_MAX = 255
KEY_LEN = 32

def H(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def verify(signature_elems, msg: bytes, pub_key_elems) -> bool:
    d = H(msg)
    out = []
    for i in range(KEY_LEN):
        v = signature_elems[i]
        for _ in range(d[i] + 1):
            v = H(v)
        out.append(v)
    return out == pub_key_elems

def main():
    with open("data_wots_up2.json", "r") as f:
        data = json.load(f)

    pub_key = [bytes.fromhex(x) for x in data["public_key"]]

    # target message (must match chal.py format exactly)
    target_msg = f"{data['public_key'][0]} sent 999999 WOTScoins to me".encode()
    target_digest = H(target_msg)

    # collect observed (digest_byte, sig_element) per position
    table = [[] for _ in range(KEY_LEN)]
    for rec in data["signatures"]:
        msg = rec["message"].encode()
        d = H(msg)
        sig = [bytes.fromhex(x) for x in rec["signature"]]
        for i in range(KEY_LEN):
            table[i].append((d[i], sig[i]))

    # sort by digest byte descending so we quickly find b_obs >= b_t
    for i in range(KEY_LEN):
        table[i].sort(key=lambda t: t[0], reverse=True)

    # forge signature for target_msg by mixing components across signatures
    forged = []
    for i in range(KEY_LEN):
        b_t = target_digest[i]
        for b_obs, elem in table[i]:
            if b_obs >= b_t:
                x = elem
                for _ in range(b_obs - b_t):
                    x = H(x)
                forged.append(x)
                break
        else:
            raise RuntimeError(f"No usable signature element for index {i}")

    assert verify(forged, target_msg, pub_key), "forgery failed (unexpected)"

    # recover AES key from first byte of each signature element (as chal.py does)
    aes_key = bytes([s[0] for s in forged])
    iv = bytes.fromhex(data["iv"])
    enc = bytes.fromhex(data["enc"])

    pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc)
    print(pt.decode(errors="replace"))

if __name__ == "__main__":
    main()