

import json
import socket
import struct
import sys
from typing import Optional, Tuple, List

HOST = "socket.cryptohack.org"
PORT = 13407


# ---------------------------
# Network / JSON plumbing
# ---------------------------

class Remote:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.f = self.s.makefile("rwb", buffering=0)

    def close(self):
        try:
            self.f.close()
        finally:
            self.s.close()

    def send_json(self, obj: dict) -> None:
        data = json.dumps(obj).encode() + b"\n"
        self.f.write(data)

    def recv_json(self) -> dict:
        """
        CryptoHack listeners often print prompts / banners as plain text.
        Keep reading lines until one parses as JSON.
        """
        while True:
            line = self.f.readline()
            if not line:
                raise EOFError("Connection closed by remote.")
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line.decode())
            except json.JSONDecodeError:
                continue


def oracle_hash(io: Remote, data_bytes: bytes) -> str:
    io.send_json({"option": "message", "data": data_bytes.hex()})
    r = io.recv_json()
    if "hash" in r:
        return r["hash"]
    raise RuntimeError(f"Oracle error for len={len(data_bytes)}: {r}")



_MD5_S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

_MD5_K = [int(abs(__import__("math").sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]


def _lrot(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def md5_padding(msg_len_bytes: int) -> bytes:
    """
    Standard MD5 padding for a message of length msg_len_bytes (before padding).
    """
    pad = b"\x80"
    zeros = (56 - (msg_len_bytes + 1) % 64) % 64
    pad += b"\x00" * zeros
    pad += struct.pack("<Q", msg_len_bytes * 8)
    return pad


def md5_compress(state: Tuple[int, int, int, int], block64: bytes) -> Tuple[int, int, int, int]:
    a, b, c, d = state
    M = list(struct.unpack("<16I", block64))

    A, B, C, D = a, b, c, d

    for i in range(64):
        if 0 <= i <= 15:
            F = (B & C) | (~B & D)
            g = i
        elif 16 <= i <= 31:
            F = (D & B) | (~D & C)
            g = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            F = B ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            F = C ^ (B | ~D)
            g = (7 * i) % 16

        F = (F + A + _MD5_K[i] + M[g]) & 0xFFFFFFFF
        A = D
        D = C
        C = B
        B = (B + _lrot(F, _MD5_S[i])) & 0xFFFFFFFF

    a = (a + A) & 0xFFFFFFFF
    b = (b + B) & 0xFFFFFFFF
    c = (c + C) & 0xFFFFFFFF
    d = (d + D) & 0xFFFFFFFF
    return a, b, c, d


def md5_digest_from_state(state: Tuple[int, int, int, int]) -> str:
    return struct.pack("<4I", *state).hex()


def md5_state_from_digest_hex(digest_hex: str) -> Tuple[int, int, int, int]:
    raw = bytes.fromhex(digest_hex)
    return struct.unpack("<4I", raw)


def md5_continue(digest_hex: str, total_len_before_append: int, append: bytes) -> str:
    
    state = md5_state_from_digest_hex(digest_hex)

    total_len = total_len_before_append + len(append)
    to_process = append + md5_padding(total_len)

    if len(to_process) % 64 != 0:
        raise ValueError("Internal error: appended+padding not multiple of 64.")

    for i in range(0, len(to_process), 64):
        state = md5_compress(state, to_process[i:i+64])

    return md5_digest_from_state(state)


# ---------------------------
# Attack logic
# ---------------------------

def find_flag_length(io: Remote, max_try: int = 256) -> int:
    
    for L in range(1, max_try + 1):
        try:
            _ = oracle_hash(io, b"\x00" * L)
            return L
        except RuntimeError:
            continue
    raise RuntimeError("Failed to determine FLAG length within max_try.")


def find_good_base_length(L: int, limit: int = 20000) -> int:
    
    target_mod64 = 55
    target_modL = L - 1
    for n in range(L, limit + 1):
        if (n % 64) == target_mod64 and (n % L) == target_modL:
            return n
    raise RuntimeError("Failed to find a suitable n; increase limit.")


def build_data_for_extended_message(
    L: int,
    key_bytes: List[Optional[int]],
    base_len: int,
    pad: bytes,
    X: bytes,
) -> bytes:
    """
    We want salted = salted0 || pad || X.

    We'll use data0 = 0^base_len, so salted0 = keycycle[:base_len].
    Then for bytes after base_len:
        data[pos] = desired_salted_byte XOR key[pos mod L]
    """
    if any(b is None for b in key_bytes):
        
        pass

    out = bytearray(b"\x00" * base_len)

    tail = pad + X
    for j, sb in enumerate(tail):
        pos = base_len + j
        ki = pos % L
        kb = key_bytes[ki]
        if kb is None:
            raise ValueError(f"Need key byte at index {ki}, but it's unknown.")
        out.append(sb ^ kb)

    return bytes(out)


def main():
    io = Remote(HOST, PORT)
    try:
        # 1) Discover L
        L = find_flag_length(io, max_try=256)
        print(f"[+] Discovered FLAG length: L = {L}")

        
        key: List[Optional[int]] = [None] * L
        known_prefix = b"crypto{"
        for i, b in enumerate(known_prefix):
            key[i] = b
        key[L - 1] = ord("}")

        # 2) Find a base length n with nice alignment
        n = find_good_base_length(L)
        print(f"[+] Using base length n = {n} (n%64=55, n%L=L-1)")

        # 3) Query base hash for data0 = 0^n  => salted0 = keycycle[:n]
        data0 = b"\x00" * n
        h0 = oracle_hash(io, data0)
        print(f"[+] h0 = MD5(salted0) = {h0}")

        pad_n = md5_padding(n)  
        if len(pad_n) != 9:
            print(f"[!] Warning: expected pad_len=9, got {len(pad_n)}")

        total_before_append = n + len(pad_n)  # this should be a multiple of 64
        if total_before_append % 64 != 0:
            print("[!] Warning: base+pad is not on a block boundary; attack still works but alignment is less pretty.")

        # 4) Recover key[7] first via X = b"" (only need the 9 padding-byte key window)
        # Padding bytes XOR against key indices:
        #   (n % L) == L-1  => indices [L-1,0,1,2,3,4,5,6,7]
        if key[7] is None:
            predicted = md5_continue(h0, total_before_append, b"")  
            print(f"[+] Predicted hash for X=empty: {predicted}")

            found = None
            for guess in range(256):
                key_try = key[:]
                key_try[7] = guess

                required = [(n + j) % L for j in range(len(pad_n))]
                ok = True
                for idx in required:
                    if key_try[idx] is None:
                        ok = False
                        break
                if not ok:
                    continue

                data_test = build_data_for_extended_message(
                    L=L,
                    key_bytes=key_try,
                    base_len=n,
                    pad=pad_n,
                    X=b"",
                )
                h_srv = oracle_hash(io, data_test)
                if h_srv == predicted:
                    found = guess
                    key[7] = guess
                    print(f"[+] Recovered FLAG[7] = {guess:#02x} ({chr(guess)!r})")
                    break

            if found is None:
                raise RuntimeError("Failed to recover FLAG[7]. (If FLAG[-1] isn't '}', brute-force it too.)")

        # 5) Recover the rest by extending with X = 0...0 (one more byte each time)
        
        start_idx = total_before_append % L
        print(f"[+] Extension starts at key index start_idx = {start_idx}")

        
        X = bytearray()
        for step in range(L):
            idx = (start_idx + step) % L

            X.append(0)

            predicted = md5_continue(h0, total_before_append, bytes(X))

            if key[idx] is not None:
                continue

            found = None
            for guess in range(256):
                key_try = key[:]
                key_try[idx] = guess

                needed_positions = list(range(n, n + len(pad_n) + len(X)))
                for pos in needed_positions:
                    ki = pos % L
                    if key_try[ki] is None:
                        
                        break
                else:
                    data_test = build_data_for_extended_message(
                        L=L,
                        key_bytes=key_try,
                        base_len=n,
                        pad=pad_n,
                        X=bytes(X),
                    )
                    h_srv = oracle_hash(io, data_test)
                    if h_srv == predicted:
                        found = guess
                        key[idx] = guess
                        printable = chr(guess) if 32 <= guess <= 126 else "."
                        print(f"[+] Recovered FLAG[{idx}] = {guess:#02x} ({printable})")
                        break

            if found is None:
                raise RuntimeError(f"Failed to recover FLAG[{idx}] at step={step}.")

        # 6) Assemble flag
        if any(b is None for b in key):
            missing = [i for i, b in enumerate(key) if b is None]
            raise RuntimeError(f"Still missing bytes at indices: {missing}")

        flag = bytes(key)
        print("\n[+] FLAG recovered:")
        print(flag.decode(errors="replace"))

    finally:
        io.close()


if __name__ == "__main__":
    main()