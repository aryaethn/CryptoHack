"""
Bad Temper 2 -- same BIP39 "wallet seed generator" (Python's MT19937), but now
the flag is gated on recovering the raw 256-bit secret handed to .seed(), not on
predicting outputs. We still get as many 32-byte wallet seeds (get_seed) as we
like, so we clone the generator AND invert the seeding.

CPython's random.seed(bytes) sets the integer seed to
    a = int.from_bytes(secret + sha512(secret), 'big')
and the C layer feeds a's little-endian 32-bit words to init_by_array, which is:
    mt = init_genrand(19650218)                         # S0, a fixed constant
    i, j = 1, 0
    for _ in range(max(624, len(key))):                 # loop1, mixes in key
        mt[i] = ((mt[i] ^ ((mt[i-1]^(mt[i-1]>>30)) * 0x19660d)) + key[j] + j) & MASK
        i += 1; j += 1
        if i >= 624: mt[0] = mt[623]; i = 1
        j %= len(key)
    for _ in range(623):                                # loop2, key-independent
        mt[i] = ((mt[i] ^ ((mt[i-1]^(mt[i-1]>>30)) * 0x5d588b65)) - i) & MASK
        i += 1
        if i >= 624: mt[0] = mt[623]; i = 1
    mt[0] = 0x80000000

Inversion:
  1. 78 get_seed calls give the full first batch B1 (624 words). Untwist once to
     get B0, the state right after init_by_array (B0[0] is lost to the single-
     batch untwist, but we never need it).
  2. loop2 doesn't involve the key and reverses position-by-position:
         S1[i] = ((B0[i] + i) ^ ((B0[i-1]^(B0[i-1]>>30)) * 0x5d588b65)) & MASK   (i>=3)
  3. The key (= a's 24 words) falls out of loop1's SECOND cycle, where every
     written position is a clean single-write with known neighbours:
         key[j] = (S1[j+25] - j - (S0[j+25] ^ ((S1[j+24]^(S1[j+24]>>30)) * 0x19660d))) & MASK
  4. Reassemble a from its words, split a.to_bytes(96,'big') into
     secret || sha512(secret); the sha512 half is a free correctness check.
"""
import hashlib
import json

from pwn import remote
from mnemonic import Mnemonic

HOST = "socket.cryptohack.org"
PORT = 13438

MASK = 0xFFFFFFFF
N, M = 624, 397
MATRIX_A = 0x9908B0DF
M1, M2 = 0x19660D, 0x5D588B65
INITGEN_SEED, INITGEN_MULT = 19650218, 0x6C078965


def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    y ^= ((y << 7) & 0x9D2C5680) ^ ((y << 14) & 0x94284000) \
        ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000)
    y ^= (y >> 11) ^ (y >> 22)
    return y & MASK


def untwist(mt):
    """Invert one twist: recover the pre-twist batch (position 0 is lost)."""
    mt = list(mt)
    for i in range(N - 1, -1, -1):
        t1 = mt[i] ^ mt[(i + M) % N]
        if (t1 >> 31) & 1:
            t1 ^= MATRIX_A
        high = (t1 >> 30) & 1
        low = 0
        t2 = mt[i - 1] ^ mt[(i + M - 1) % N]
        if (t2 >> 31) & 1:
            t2 ^= MATRIX_A
            low = 1
        mt[i] = (high << 31) | ((t2 & 0x3FFFFFFF) << 1) | low
    return mt


def init_genrand(seed):
    mt = [0] * N
    mt[0] = seed & MASK
    for i in range(1, N):
        mt[i] = (INITGEN_MULT * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & MASK
    return mt


S0 = init_genrand(INITGEN_SEED)


def recover_secret(wallet_seeds):
    words = []
    for ws in wallet_seeds:
        v = int.from_bytes(ws, "little")
        words += [(v >> (32 * k)) & MASK for k in range(8)]
    assert len(words) == N

    B0 = untwist([untemper(w) for w in words])

    S1 = {}
    for i in range(3, 50):
        S1[i] = ((B0[i] + i) ^ ((B0[i - 1] ^ (B0[i - 1] >> 30)) * M2)) & MASK

    keys = [(S1[j + 25] - j - (S0[j + 25] ^ ((S1[j + 24] ^ (S1[j + 24] >> 30)) * M1))) & MASK
            for j in range(24)]

    a = sum(k << (32 * idx) for idx, k in enumerate(keys))
    blob = a.to_bytes(96, "big")
    secret, tail = blob[:32], blob[32:]
    assert hashlib.sha512(secret).digest() == tail, "sha512 self-check failed"
    return secret


def main():
    mnemo = Mnemonic("english")
    io = remote(HOST, PORT)

    def recv_json():
        while True:
            line = io.recvline(timeout=10)
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    wallet_seeds = []
    for _ in range(78):  # 78 * 32 bytes = 624 words = the full first MT batch B1
        io.sendline(json.dumps({"option": "get_seed"}).encode())
        wallet_seeds.append(mnemo.to_entropy(recv_json()["wallet_seed"]))

    secret = recover_secret(wallet_seeds)
    io.sendline(json.dumps({"option": "secret", "secret": secret.hex()}).encode())
    print(recv_json())
    io.close()


if __name__ == "__main__":
    main()
