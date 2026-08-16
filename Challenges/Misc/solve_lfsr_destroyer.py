"""
LFSR Destroyer -- live/time-limited part (must complete within TIMEOUT=15s).

Loads the equation rows precomputed by precompute_lfsr_destroyer.py, grabs
2500 bytes of raw keystream via a chosen (all-zero) plaintext, selects the
precomputed row for every bit that came out 1, and solves the resulting
GF(2) linear system for the 128-bit key. See precompute_lfsr_destroyer.py
for the full explanation of the attack.
"""
import json
import time

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13404

D = 128
LIMIT_BYTES = 2500

t_start = time.time()

with open("lfsr_destroyer_rows.bin", "rb") as f:
    NCOLS = int.from_bytes(f.read(4), "little")
    NROWS = int.from_bytes(f.read(4), "little")
    nbytes = (NCOLS + 7) // 8
    rows = []
    for _ in range(NROWS):
        rows.append(int.from_bytes(f.read(nbytes), "little"))
print(f"[+] loaded {NROWS} precomputed rows in {time.time()-t_start:.2f}s")


def try_solve(rows_int):
    pivots = {}
    for m in rows_int:
        while m:
            p = m.bit_length() - 1
            entry = pivots.get(p)
            if entry is None:
                pivots[p] = m
                break
            m ^= entry
    return pivots


def extract_key(pivots, ncols):
    free_cols = [c for c in range(ncols) if c not in pivots]
    assert len(free_cols) == 1, f"expected a 1-dim kernel, got {len(free_cols)}"
    free = free_cols[0]

    resolved = {free: 1}
    for p in sorted(pivots.keys()):
        m = pivots[p]
        val = 0
        mm = m & ~(1 << p)
        while mm:
            q = mm.bit_length() - 1
            mm &= ~(1 << q)
            val ^= resolved[q]
        resolved[p] = val

    return [resolved.get(i, 0) for i in range(D)]


r = remote(HOST, PORT)
r.recvline()

req = json.dumps({"option": "encrypt", "plaintext": ("00" * LIMIT_BYTES)}).encode()
r.sendline(req)
resp = json.loads(r.recvline())
ks = bytes.fromhex(resp["ciphertext"])
print(f"[+] got {len(ks)} bytes of keystream at {time.time()-t_start:.2f}s")

bits = []
for byte in ks:
    for i in range(7, -1, -1):
        bits.append((byte >> i) & 1)

selected = [rows[n] for n in range(len(bits)) if bits[n] == 1]
print(f"[+] {len(selected)} usable equations")

pivots = try_solve(selected)
print(f"[+] elimination done at {time.time()-t_start:.2f}s, rank={len(pivots)}/{NCOLS}")

key_bits = extract_key(pivots, NCOLS)
key_int = int("".join(map(str, key_bits)), 2)
print(f"[+] recovered key at {time.time()-t_start:.2f}s: {key_int}")

r.sendline(json.dumps({"option": "get_flag", "key": str(key_int)}).encode())
final = json.loads(r.recvline())
print(final)

r.close()
