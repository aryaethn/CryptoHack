"""
Rhetorical Oracle -- the server AES-CBC-encrypts {"user_id": <random token>}
and will hand us the flag if we submit a ciphertext that decrypts (under its
secret key) to {"user_id": <one of two admin tokens>} with valid padding.
It leaks nothing about plaintext except whether PKCS#7 unpadding succeeded
("good_pad": true/false) -- a textbook CBC padding oracle.

A padding oracle doesn't just decrypt, it lets us *forge*: in CBC,
plaintext_block = AES_decrypt(key, C) XOR previous_block, and we control the
previous block (or IV) freely. So for any ciphertext block C we can recover
the intermediate value I = AES_decrypt(key, C) via the standard byte-at-a-
time oracle attack, then pick the preceding block to be I XOR target_block,
forcing that block to decrypt to whatever plaintext we want.

The admin JSON is 79 bytes -> pads to 80 bytes (5 blocks). We chain the
forgery backwards: start from an arbitrary last ciphertext block, recover
its intermediate value, derive the block before it to hit our target
plaintext block, recover *that* block's intermediate value, and so on back
to a forged IV. Concatenating gives a 6-block ciphertext (IV + 5 blocks)
that decrypts to exactly the admin JSON.

Quirk: the server caps each socket message at 1024 bytes and resets the
connection if too many requests are pipelined without being read, so guesses
are sent in chunks of 6 (comfortably under the limit), synchronously.
"""
import json
import os

from Crypto.Util.Padding import pad
from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13436
ADMIN_ID = "0656d38b8cb0b41b82ecc9859cb7c03e53c7c6610bdce9ea14d30d1a33c80204"
CHUNK = 6  # max requests per send() call (server allows up to 1024 bytes/message)

target = pad(json.dumps({"user_id": ADMIN_ID}).encode(), 16)
blocks = [target[i:i + 16] for i in range(0, len(target), 16)]


class FoundFlag(Exception):
    pass


def query(io, hex_candidates):
    io.send(b"".join((json.dumps({"ciphertext": c}) + "\n").encode() for c in hex_candidates))
    results = []
    for _ in hex_candidates:
        resp = json.loads(io.recvline())
        if "flag" in resp:
            raise FoundFlag(resp["flag"])
        results.append(resp["good_pad"])
    return results


def find_intermediate(io, block):
    """Recover I = AES_decrypt(key, block) via the padding oracle."""
    I = bytearray(16)
    for pad_len in range(1, 17):
        probe = bytearray(16)
        for k in range(1, pad_len):
            probe[16 - k] = I[16 - k] ^ pad_len

        candidates = []
        for g in range(256):
            probe[16 - pad_len] = g
            candidates.append((bytes(probe) + block).hex())

        hits = []
        for i in range(0, 256, CHUNK):
            results = query(io, candidates[i:i + CHUNK])
            hits += [i + j for j, r in enumerate(results) if r]
            if hits and pad_len > 1:  # pad_len==1 can collide, scan fully then disambiguate
                break

        if pad_len == 1 and len(hits) > 1:
            for g in hits:
                probe[15] = g
                probe[14] ^= 0xFF
                ok = query(io, [(bytes(probe) + block).hex()])[0]
                probe[14] ^= 0xFF
                if ok:
                    g_final = g
                    break
            else:
                raise RuntimeError("padding ambiguity could not be resolved")
        else:
            g_final = hits[0]

        I[16 - pad_len] = g_final ^ pad_len
    return bytes(I)


def main():
    io = remote(HOST, PORT)
    io.recvline()  # initial {"token": ...}, unused: we forge our own ciphertext

    n = len(blocks)
    K = [None] * (n + 1)
    K[n] = os.urandom(16)

    try:
        for i in range(n, 0, -1):
            I_i = find_intermediate(io, K[i])
            K[i - 1] = bytes(a ^ b for a, b in zip(I_i, blocks[i - 1]))

        forged = b"".join(K)
        print(query(io, [forged.hex()]))
    except FoundFlag as e:
        print(e.args[0])


if __name__ == "__main__":
    main()
