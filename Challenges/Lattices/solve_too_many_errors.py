#!/usr/bin/env python3
from pwn import remote, context
import json
import time
from collections import Counter

context.log_level = "error"   # change to "info" or "debug" if you want verbose IO

HOST = "socket.cryptohack.org"
PORT = 13390
q = 127

# ---------- JSON I/O over line protocol ----------
def recv_json(io):
    """
    CryptoHack often sends a banner / non-JSON lines.
    This reads lines until it finds a JSON object.
    """
    while True:
        line = io.recvline(timeout=6)
        if not line:
            raise EOFError("timeout / connection closed")
        line = line.strip()
        if not line:
            continue
        if line.startswith(b"{") and line.endswith(b"}"):
            return json.loads(line.decode())
        # else: banner/noise, ignore

def send_json(io, obj):
    io.sendline(json.dumps(obj).encode())

def request(io, obj):
    send_json(io, obj)
    return recv_json(io)

def connect():
    io = remote(HOST, PORT, timeout=6)
    # try to eat one JSON/banner chunk if present
    try:
        txt = recv_json(io)
        print(txt)
    except Exception:
        pass
    return io

# ---------- math helpers ----------
def mode(vals):
    return Counter(vals).most_common(1)[0][0]

def inv_mod(a, p):
    a %= p
    if a == 0:
        raise ZeroDivisionError("no inverse")
    return pow(a, p - 2, p)  # p is prime

def infer_a0(samples, n):
    a0 = []
    for i in range(n):
        a0.append(mode([a[i] for (a, b) in samples]))
    return a0

def recover_votes(samples, a0, b0):
    n = len(a0)
    votes = [Counter() for _ in range(n)]
    for (a, b) in samples:
        diffs = [i for i, (x, y) in enumerate(zip(a, a0)) if x != y]
        if len(diffs) != 1:
            continue  # unfaulted or weird
        k = diffs[0]
        denom = (a[k] - a0[k]) % q
        if denom == 0:
            continue
        diff = (b - b0) % q
        sk = (diff * inv_mod(denom, q)) % q
        votes[k][sk] += 1
    return votes

def assemble(votes, min_support=3):
    s = []
    supports = []
    for v in votes:
        if not v:
            s.append(None); supports.append(0); continue
        val, cnt = v.most_common(1)[0]
        s.append(val); supports.append(cnt)
    if any(x is None or c < min_support for x, c in zip(s, supports)):
        return None, supports
    return bytes(s), supports

# ---------- main loop ----------
def main():
    io = connect()
    print("Connected to server")
    samples = []
    n = None

    batch = 100
    max_samples = 6000
    min_support = 3

    collected = 0
    while collected < max_samples:
        print(f"Entering Batch {collected}")
        for _ in range(batch):
            try:
                request(io, {"option": "reset"})
                resp = request(io, {"option": "get_sample"})
                a, b = resp["a"], resp["b"]

                if n is None:
                    n = len(a)

                samples.append((a, b))
                collected += 1

                # If you still get disconnects often, uncomment a tiny throttle:
                # time.sleep(0.002)

            except Exception:
                # server closed / timeout / parse issue -> reconnect
                try:
                    io.close()
                except Exception:
                    pass
                io = connect()
                continue

        # compute after each batch
        a0 = infer_a0(samples, n)
        b0 = mode([b for (_, b) in samples])
        votes = recover_votes(samples, a0, b0)
        flag, supports = assemble(votes, min_support=min_support)
        have = sum(1 for c in supports if c >= min_support)

        print(f"samples={collected} recovered>={min_support}: {have}/{n}")

        if flag is not None:
            if flag.startswith(b"crypto{") and flag.endswith(b"}") and len(flag) == n:
                print(flag.decode())
                return

    print("Not enough stability/votes. Try: increase max_samples, or set min_support=2, or add small sleep.")

if __name__ == "__main__":
    main()
