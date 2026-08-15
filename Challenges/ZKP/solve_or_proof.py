import random
import re

from pwn import remote

HOST = "archive.cryptohack.org"
PORT = 11840

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Known witness for the g^w0 = y0 branch (handed to us directly by the source)
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617

r = remote(HOST, PORT)

# ---------------------------------------------------------------------------
# Phase 1: correctness -- OR-proof for "I know w0 or w1"
#
# We really only know w0. Run branch 0 honestly (r0, a0 = g^r0). Simulate
# branch 1 (the HVZK simulator): pick e1 and z1 freely, then back out
# a1 = y1^-e1 * g^z1 so g^z1 = a1*y1^e1 holds unconditionally. Once the
# verifier reveals s, set e0 = s XOR e1 (forcing e0^e1==s) and complete
# branch 0 honestly with z0 = r0 + e0*w0 mod q.
# ---------------------------------------------------------------------------
r0 = random.randint(0, q - 1)
a0 = pow(g, r0, p)

e1 = random.randint(0, 2**511 - 1)
z1 = random.randint(0, q - 1)
a1 = (pow(y1, -e1, p) * pow(g, z1, p)) % p

r.sendlineafter(b"a0:", str(a0).encode())
r.sendlineafter(b"a1:", str(a1).encode())

line = r.recvline().decode()
s = int(re.search(r"s = (\d+)", line).group(1))

e0 = s ^ e1
z0 = (r0 + e0 * w0) % q

r.sendlineafter(b"e0:", str(e0).encode())
r.sendlineafter(b"e1:", str(e1).encode())
r.sendlineafter(b"z0:", str(z0).encode())
r.sendlineafter(b"z1:", str(z1).encode())

# ---------------------------------------------------------------------------
# Phase 2: specialSoundness -- server rewinds itself and shows us two
# accepting transcripts for the same commitments (a0,a1) but two different
# challenges s, s*. Exactly one branch's (e_i, z_i) differs between the two
# transcripts (the honest branch, which is re-derived from the new s); the
# other branch is the fixed simulated one. Standard OR special-soundness
# extraction: w_i = (z_i - z_i*) / (e_i - e_i*) mod q for whichever branch
# actually changed.
# ---------------------------------------------------------------------------
def read_kv_lines(n):
    kv = {}
    while len(kv) < n:
        line = r.recvline().decode().strip()
        if not line or " = " not in line:
            continue
        key, val = line.split(" = ")
        kv[key.rstrip("*")] = int(val)
    return kv

r.recvuntil(b"transcript 1:")
t1 = read_kv_lines(7)

r.recvuntil(b"transcript 2:")
t2 = read_kv_lines(7)

assert t1["a0"] == t2["a0"] and t1["a1"] == t2["a1"]

if t1["e0"] != t2["e0"]:
    e_diff = (t1["e0"] - t2["e0"]) % q
    z_diff = (t1["z0"] - t2["z0"]) % q
else:
    assert t1["e1"] != t2["e1"]
    e_diff = (t1["e1"] - t2["e1"]) % q
    z_diff = (t1["z1"] - t2["z1"]) % q

wb = (z_diff * pow(e_diff, -1, q)) % q

r.sendlineafter(b"give me a witness!", str(wb).encode())

# ---------------------------------------------------------------------------
# Phase 3: SHVZK -- server hands us fresh y0,y1 and a target s, and we must
# produce a full satisfying transcript without knowing either witness. Same
# simulator trick as phase 1, applied to *both* branches this time.
# ---------------------------------------------------------------------------
y0_s = y1_s = s_shvzk = None
while y0_s is None or y1_s is None or s_shvzk is None:
    line = r.recvline().decode().strip()
    if line.startswith("y0 = "):
        y0_s = int(line.split(" = ")[1])
    elif line.startswith("y1 = "):
        y1_s = int(line.split(" = ")[1])
    elif "give me satisfying transcript for s = " in line:
        s_shvzk = int(line.split("s = ")[1])

e0_sim = random.randint(0, 2**511 - 1)
e1_sim = e0_sim ^ s_shvzk
z0_sim = random.randint(0, q - 1)
z1_sim = random.randint(0, q - 1)
a0_sim = (pow(y0_s, -e0_sim, p) * pow(g, z0_sim, p)) % p
a1_sim = (pow(y1_s, -e1_sim, p) * pow(g, z1_sim, p)) % p

r.sendlineafter(b"a0:", str(a0_sim).encode())
r.sendlineafter(b"a1:", str(a1_sim).encode())
r.sendlineafter(b"e0:", str(e0_sim).encode())
r.sendlineafter(b"e1:", str(e1_sim).encode())
r.sendlineafter(b"z0:", str(z0_sim).encode())
r.sendlineafter(b"z1:", str(z1_sim).encode())

print(r.recvall(timeout=5).decode())
