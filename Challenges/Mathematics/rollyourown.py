from Crypto.Util.number import *
from pwn import remote
import json


r = remote('socket.cryptohack.org', 13403)
p = int(r.recvline().decode().split('"')[1], 16)
print(f"p: {p}")

r.recvuntil(b':')
r.send(json.dumps({'g': hex(p + 1), 'n': hex(p ** 2)}).encode())
print(f"g: {p + 1}")
print(f"n: {p ** 2}")
key = int(r.recvline().decode().split('"')[1], 16)
print(f"key: {key}")

r.recvuntil(b':')
x = (key - 1) // p
print(f"x: {x}")
r.send(json.dumps({'x': hex(x)}).encode())
print(f"flag: {json.loads(r.recvline().decode())['flag']}")