import base64
import json

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13370

FLAG_LEN = 20
UNKNOWN_POS = range(7, 19)  # "crypto{" (0-6) and "}" (19) are already known

r = remote(HOST, PORT)
print(r.recvline().decode())

seen = [set() for _ in range(FLAG_LEN)]

req = json.dumps({"msg": "request"}).encode()

rounds = 0
while True:
    r.sendline(req)
    resp = json.loads(r.recvline())
    if "ciphertext" not in resp:
        continue
    ct = base64.b64decode(resp["ciphertext"])
    for i, b in enumerate(ct):
        seen[i].add(b)

    rounds += 1
    if rounds % 200 == 0:
        missing_counts = [255 - len(seen[i]) for i in UNKNOWN_POS]
        print(f"round {rounds}: missing counts per unknown byte = {missing_counts}")

    if all(len(seen[i]) >= 255 for i in UNKNOWN_POS):
        break

flag_bytes = bytearray(b"crypto{" + b"?" * 12 + b"}")
for i in UNKNOWN_POS:
    full = set(range(256))
    missing = full - seen[i]
    assert len(missing) == 1, (i, missing)
    flag_bytes[i] = missing.pop()

print(rounds, "rounds")
print(flag_bytes.decode())
