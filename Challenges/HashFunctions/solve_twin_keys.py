#!/usr/bin/env python3
import json
import hashlib
from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13397

KEY_START = b"CryptoHack Secure Safe"

# Update these to whatever cpc.sh produced in your workdir
COLLISION_FILE_1 = "./hashclash/generic_workdir/collision1.bin"
COLLISION_FILE_2 = "./hashclash/generic_workdir/collision2.bin"

def load_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def md5(b: bytes) -> bytes:
    return hashlib.md5(b).digest()

def recv_json(io) -> dict:
    """
    CryptoHack 'listener' usually replies with JSON per line.
    Sometimes there's a plaintext banner first, so we skip non-JSON lines.
    """
    while True:
        line = io.recvline(timeout=5)
        if not line:
            raise RuntimeError("Server closed connection / timeout.")
        line = line.strip()
        # Try parse JSON
        try:
            return json.loads(line.decode())
        except Exception:
            # probably the plaintext before_input banner
            continue

def send_json(io, obj: dict) -> dict:
    io.sendline(json.dumps(obj).encode())
    return recv_json(io)

def main():
    k1 = load_bytes(COLLISION_FILE_1)
    k2 = load_bytes(COLLISION_FILE_2)

    if k1 == k2:
        raise ValueError("Collision files are identical; need two different keys.")

    h1 = md5(k1)
    h2 = md5(k2)
    print("MD5(k1) =", h1.hex())
    print("MD5(k2) =", h2.hex())
    if h1 != h2:
        raise ValueError("Not a collision: MD5 digests differ.")

    starts1 = k1.startswith(KEY_START)
    starts2 = k2.startswith(KEY_START)
    print("k1 startswith KEY_START?", starts1)
    print("k2 startswith KEY_START?", starts2)
    if (starts1 + starts2) != 1:
        raise ValueError("Server requires exactly ONE key to start with KEY_START.")

    io = remote(HOST, PORT)

    # Insert both keys
    r = send_json(io, {"option": "insert_key", "key": k1.hex()})
    print("insert_key(k1):", r)

    r = send_json(io, {"option": "insert_key", "key": k2.hex()})
    print("insert_key(k2):", r)

    # Unlock
    r = send_json(io, {"option": "unlock"})
    print("unlock:", r)

    io.close()

if __name__ == "__main__":
    main()