#!/usr/bin/env python3
from pwn import remote
import json
from collections import Counter

HOST = "socket.cryptohack.org"
PORT = 13402

# Use an upper bound >= real flag length so the server won't pad.
# CryptoHack flags are usually ~39 bytes, 64 is safe.
LMAX = 64

def recv_json(io):
    return json.loads(io.recvline().decode())

def send_json(io, obj):
    io.sendline(json.dumps(obj).encode())

def mix(io, data: bytes) -> str:
    send_json(io, {"option": "mix", "data": data.hex()})
    r = recv_json(io)
    if "mixed" not in r:
        raise RuntimeError(f"Bad response: {r}")
    return r["mixed"]

def bit_is_set(io, pos: int, bit: int, max_queries=100, collision_threshold=2) -> bool:
    """
    Returns True if FLAG[pos] has this bit set, else False.

    Heuristic:
    - If bit NOT set => only 256 possible digests => collisions pile up fast.
    - If bit set     => ~65536 possible digests => collisions are rare.
    """
    data = bytearray(LMAX)
    data[pos] = 1 << bit

    seen = set()
    collisions = 0

    for _ in range(max_queries):
        h = mix(io, bytes(data))
        # print("h: ", h)
        if h in seen:
            collisions += 1
            if collisions >= collision_threshold:
                # Many collisions => small support => bit is NOT set
                return False
        else:
            seen.add(h)

    # Few/no collisions => large support => bit IS set
    return True

def main():
    io = remote(HOST, PORT)
    # server prints a banner line before JSON responses
    # (Challenge.before_input). Read it if present.
    try:
        banner = io.recvline(timeout=1)
        print(banner)
        # print(banner.decode(errors="ignore"), end="")
    except EOFError:
        pass

    flag = bytearray(LMAX)

    for i in range(LMAX):
        print("i: ", i)
        val = 0
        for b in range(8):
            if bit_is_set(io, i, b):
                val |= (1 << b)
        flag[i] = val
        print("val: ", val)

        ch = chr(val) if 32 <= val < 127 else "."
        print(f"{i:02d}: 0x{val:02x} {ch}   | {bytes(flag[:i+1])}")

        # early stop once we’ve got a plausible end
        if i >= 7 and flag[i] == ord('}') and flag[:7] == b"crypto{":
            break

    print("\nRecovered (raw):", bytes(flag))
    print("Recovered (trim):", bytes(flag).split(b"\x00", 1)[0])

    io.close()

if __name__ == "__main__":
    main()