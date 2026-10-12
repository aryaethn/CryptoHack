"""
Seventy-Two -- bcrypt silently truncates its input to the first 72 bytes;
anything after that is never hashed. Each stored credential is
bcrypt(f"{TENANT}|{username}|{password}"), meant to bind the hash to both
tenant and account. But TENANT ("7f3ac1e0-...-2e8f5b04d719", 36 bytes) and
the account name are both fixed and public (sent to us in before_input),
so the attacker-known prefix f"{TENANT}|{username}|" has a fixed length
for each account -- and for "k.barrymore@corp.bluerock.example" that
prefix is exactly 71 bytes, leaving only ONE byte of the real (32-char
random) password inside bcrypt's 72-byte window. Every other password
byte is truncated away and never checked.

So we don't need the real password at all -- just its first character,
drawn from a 62-symbol charset (ascii_letters + digits). Brute-force all
62 single-character passwords for that account; whichever one matches
the real first byte reproduces the exact same first-72-bytes bcrypt
actually hashed, so checkpw() accepts it.
"""
import json
import string

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13433
USERNAME = "k.barrymore@corp.bluerock.example"

io = remote(HOST, PORT)
io.recvline()

for c in string.ascii_letters + string.digits:
    io.sendline(json.dumps({"username": USERNAME, "password": c}).encode())
    resp = json.loads(io.recvline())
    if "Flag" in resp.get("msg", ""):
        print(resp["msg"])
        break
