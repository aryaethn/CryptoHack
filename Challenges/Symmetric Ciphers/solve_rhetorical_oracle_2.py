"""
Rhetorical Oracle 2 -- same padding-oracle-forgery idea as Rhetorical
Oracle, but the server now keeps the IV fixed and secret for the whole
connection (only ciphertext.hex() is sent to us, not iv+ciphertext). That
kills the trick of directly choosing the IV: in CBC, plaintext_block_1 =
AES_decrypt(key, C_1) XOR iv, and since iv is fixed and unknown, we cannot
pick C_1 to force block 1's plaintext to anything in particular -- D(C_1)
is a PRP output we can only *learn*, never invert, so there is no way to
solve "D(C_1) = target XOR iv" for a chosen target.

Trick: reuse the server's own original ciphertext block 0 (orig_C0) as our
block 0. Its plaintext is always D(orig_C0) XOR iv -- exactly the server's
real first block, '{"user_id": "' (13 known bytes) followed by 3 unknown
but harmless hex digits (the start of the real random token). We never
need to know this value, only that it's safe (no '"' or '\\').

That leaves exactly one more "uncontrolled" block (call it B1, right after
the reused anchor) whose plaintext comes out as a side effect of the
backward chain rather than something we pick -- same reasoning as above,
shifted one block later, since B1 is also decrypted before anything we
control gets XORed in for ITS position. We absorb B1 into the still-open
JSON string from block 0, and retry with a fresh random last block (which
changes B1 unpredictably via AES's avalanche effect) until its plaintext
happens to avoid '"' (0x22) and '\\' (0x5c) -- about an 88% hit rate per
try (254/256 safe values per byte, 16 bytes: (254/256)**16).

From there on, blocks are fully under our control (standard backward
chaining, same as Rhetorical Oracle): close the first (meaningless) string,
open a second "user_id" key with the real admin id, and close the object.
json.loads keeps only the *last* value for a duplicate key, so the earlier,
uncontrolled "user_id" is simply overwritten.

Quirk: despite the 4096-byte max_payload_size in the source, a single
send() is still capped at ~1024 bytes before the connection resets, so
oracle guesses are still sent in small chunks.
"""
import json
import os

from Crypto.Util.Padding import pad
from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13437
ADMIN_ID = "0656d38b8cb0b41b82ecc9859cb7c03e53c7c6610bdce9ea14d30d1a33c80204"
CHUNK = 12  # requests per send() call; 13 (1079 bytes) reliably resets the connection

target_text = '", "user_id": "' + ADMIN_ID + '"}'
target2 = pad(target_text.encode(), 16)
blocks2 = [target2[i:i + 16] for i in range(0, len(target2), 16)]
k = len(blocks2)


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
        for j in range(1, pad_len):
            probe[16 - j] = I[16 - j] ^ pad_len

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


def attempt(io, B0):
    """Backward-chain target2, derive the uncontrolled block B1, and report
    whether its plaintext (XORed against the fixed anchor B0) is safe."""
    M = [None] * k
    M[k - 1] = os.urandom(16)

    for i in range(k - 1, 0, -1):
        I_i = find_intermediate(io, M[i])
        M[i - 1] = bytes(a ^ b for a, b in zip(I_i, blocks2[i]))

    I_0 = find_intermediate(io, M[0])
    B1 = bytes(a ^ b for a, b in zip(I_0, blocks2[0]))

    I_B1 = find_intermediate(io, B1)
    P1 = bytes(a ^ b for a, b in zip(I_B1, B0))

    safe = 0x22 not in P1 and 0x5C not in P1
    return B1, M, safe


def main():
    io = remote(HOST, PORT)
    orig_ct = bytes.fromhex(json.loads(io.recvline())["token"])
    B0 = orig_ct[:16]  # reused verbatim as our own block 0

    try:
        while True:
            B1, M, safe = attempt(io, B0)
            if safe:
                break

        forged = B0 + B1 + b"".join(M)
        print(query(io, [forged.hex()]))
    except FoundFlag as e:
        print(e.args[0])


if __name__ == "__main__":
    main()
