import os
import source_hash_stuffing as H

BS = H.BLOCK_SIZE  # 32

def rotl(b: bytes, x: int) -> bytes:
    x %= BS
    return b[x:] + b[:x]

def rotr(b: bytes, x: int) -> bytes:
    x %= BS
    return b[-x:] + b[:-x]

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

W = H.W_bytes
X = H.X_bytes

# --- Inverses for the building blocks ---

def unscramble_block(block: bytes) -> bytes:
    for _ in range(40):
        block = rotl(block, 17)
        block = xor(block, X)
        block = rotr(block, 6)
        block = xor(block, W)
    return block

def step_i(m: bytes, i: int) -> bytes:
    # One iteration of the per-index mixing step in cryptohash()
    m = rotr(m, i + 11)
    m = xor(m, X)
    m = rotl(m, i + 6)
    return m

def step_i_inv(m: bytes, i: int) -> bytes:
    # Inverse of step_i
    m = rotr(m, i + 6)     # inverse of rotl
    m = xor(m, X)          # xor is self-inverse
    m = rotl(m, i + 11)    # inverse of rotr
    return m

def F(block: bytes, i: int) -> bytes:
    m = H.scramble_block(block)
    for _ in range(i):
        m = step_i(m, i)
    return m

def F_inv(mix: bytes, i: int) -> bytes:
    m = mix
    for _ in range(i):
        m = step_i_inv(m, i)
    return unscramble_block(m)

# --- Collision construction for 2-block (64-byte) messages ---

def find_two_block_collision():
    # Pick any 2-block message M = b0||b1 (length 64 => no padding in your scheme)
    b0 = os.urandom(BS)
    b1 = os.urandom(BS)

    # Pick a different b0'
    while True:
        b0p = os.urandom(BS)
        if b0p != b0:
            break

    # We want:
    #   F(b0,0) xor F(b1,1) == F(b0',0) xor F(b1',1)
    # => F(b1',1) = F(b0,0) xor F(b1,1) xor F(b0',0)
    target = xor(xor(F(b0, 0), F(b1, 1)), F(b0p, 0))
    b1p = F_inv(target, 1)

    m1 = b0 + b1
    m2 = b0p + b1p

    assert m1 != m2
    h1 = H.cryptohash(m1)
    h2 = H.cryptohash(m2)
    assert h1 == h2

    return m1, m2, h1


m1, m2, digest = find_two_block_collision()
print("Collision found!")
print("digest =", digest)
print("m1(hex) =", m1.hex())
print("m2(hex) =", m2.hex())
print("len(m1) =", len(m1), "len(m2) =", len(m2))


from pwn import *
import json

HOST = "socket.cryptohack.org"
PORT = 13405

r = remote(HOST, PORT)

inp = r.recvline()
print(inp)
inp = r.recvline()
print(inp)

rec = json.dumps({"m1": m1.hex(), "m2": m2.hex()})
r.sendline(rec)

inp = r.recvline()
print(inp)
