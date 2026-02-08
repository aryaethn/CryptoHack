#!/usr/bin/env python3
import os
import ast
import json
import socket
from typing import List, Tuple, Optional

CHAL_FILE = "13395.py"
HOST = "socket.cryptohack.org"
PORT = 13395

def load_sbox_from_file(path: str) -> List[int]:
    """
    Parse SBOX = [...] from the challenge file without importing it
    (import would fail due to utils.listener).
    """
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "SBOX":
                    sbox = ast.literal_eval(node.value)
                    if not (isinstance(sbox, list) and len(sbox) == 256):
                        raise ValueError("SBOX did not look like a 256-byte table.")
                    return sbox

    raise ValueError("Could not find SBOX in the file.")

def permute(block: List[int]) -> List[int]:
    # permute(permute(x)) = x and permute linear over XOR
    result = [0 for _ in range(8)]
    for i in range(8):
        x = block[i]
        for j in range(8):
            result[j] |= (x & 1) << i
            x >>= 1
    return result

def make_hash_funcs(SBOX: List[int]):
    def substitute(block: List[int]) -> List[int]:
        return [SBOX[x] for x in block]

    def h(data: bytes) -> Optional[bytes]:
        if len(data) % 4 != 0:
            return None

        state = [16, 32, 48, 80, 80, 96, 112, 128]
        for i in range(0, len(data), 4):
            b = data[i:i+4]
            state[4] ^= b[0]
            state[5] ^= b[1]
            state[6] ^= b[2]
            state[7] ^= b[3]
            state = permute(state)
            state = substitute(state)

        for _ in range(16):
            state = permute(state)
            state = substitute(state)

        out = []
        for _ in range(2):
            out += state[4:]
            state = permute(state)
            state = substitute(state)

        return bytes(out)

    return h

def find_collision(h) -> Tuple[bytes, bytes, bytes]:
    """
    Birthday search on 8-byte hash outputs using random 4-byte inputs.
    Very fast here because the construction is extremely lossy.
    """
    seen = {}  # hash -> message
    while True:
        m = os.urandom(4)
        d = h(m)
        if d in seen and seen[d] != m:
            return seen[d], m, d
        seen[d] = m

def recv_some(sock: socket.socket) -> str:
    sock.settimeout(2.0)
    try:
        data = sock.recv(4096)
        return data.decode(errors="replace")
    except Exception:
        return ""

def submit_to_server(a: bytes, b: bytes):
    payload = {"a": a.hex(), "b": b.hex()}
    with socket.create_connection((HOST, PORT), timeout=5.0) as s:
        banner = recv_some(s)
        if banner:
            print(banner, end="")

        s.sendall((json.dumps(payload) + "\n").encode())
        resp = recv_some(s)
        print(resp)

def main():
    SBOX = load_sbox_from_file(CHAL_FILE)
    h = make_hash_funcs(SBOX)

    # Known collision
    a = bytes.fromhex("45a7f1fd")
    b = bytes.fromhex("4da7f9f5")
    if h(a) == h(b) and a != b:
        digest = h(a)
        print("[+] Using known collision:")
        print("    a =", a.hex())
        print("    b =", b.hex())
        print("    h =", digest.hex())
    else:
        print("[*] Known pair did not verify (file differs?). Searching...")
        a, b, digest = find_collision(h)
        print("[+] Found collision:")
        print("    a =", a.hex())
        print("    b =", b.hex())
        print("    h =", digest.hex())

    # Uncomment to submit
    submit_to_server(a, b)

if __name__ == "__main__":
    main()