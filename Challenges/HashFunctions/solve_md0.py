#!/usr/bin/env python3
import json
import socket
from Crypto.Cipher import AES

HOST = "socket.cryptohack.org"
PORT = 13388

def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad_for_len(msg_len: int, bs: int = 16) -> bytes:
    padlen = bs - (msg_len % bs)
    if padlen == 0:
        padlen = bs
    return bytes([padlen]) * padlen

def continue_hash(state: bytes, data: bytes) -> bytes:
    assert len(state) == 16
    assert len(data) % 16 == 0
    out = state
    for i in range(0, len(data), 16):
        blk = data[i:i+16]                 # this becomes the AES key
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out

class Remote:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        # read banner line if present
        self.s.recv(4096)

    def req(self, obj):
        self.s.sendall((json.dumps(obj) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.s.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed")
            data += chunk
        return json.loads(data.decode())

def main():
    r = Remote(HOST, PORT)

    key_len = 16

    # 1) get a real signature for a safe message (must NOT contain b"admin=True")
    m = b"comment=hello;user=arya"  # any bytes are fine as long as it avoids admin=True
    resp = r.req({"option": "sign", "message": m.hex()})
    if "signature" not in resp:
        raise RuntimeError(resp)
    sig = bytes.fromhex(resp["signature"])
    print("[+] got signature:", sig.hex())

    # 2) compute glue padding for (key||m) length
    glue = pkcs7_pad_for_len(key_len + len(m), 16)

    # 3) choose extra that grants admin
    extra = b"admin=True"

    # message we will send to get_flag
    forged_message = m + glue + extra

    # 4) continue the hash starting from the returned signature as chaining state
    # The server will compute hash(key || forged_message) with PKCS#7 at the end.
    total_len_before_final_pad = key_len + len(forged_message)
    final_pad = pkcs7_pad_for_len(total_len_before_final_pad, 16)

    forged_sig = continue_hash(sig, extra + final_pad)
    print("[+] forged signature:", forged_sig.hex())

    # 5) submit forged pair
    resp = r.req({
        "option": "get_flag",
        "message": forged_message.hex(),
        "signature": forged_sig.hex()
    })
    print(resp)

if __name__ == "__main__":
    main()