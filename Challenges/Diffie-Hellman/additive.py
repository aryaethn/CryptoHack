import pwn
import json
import hashlib
import random
from Crypto.Cipher import AES
from sympy.ntheory import discrete_log

io = pwn.remote("socket.cryptohack.org", 13380)
io.recvuntil(b'Intercepted from Alice: ')
alice = json.loads(io.recvline())
p_hex, g_hex, A_hex = alice['p'], alice['g'], alice['A']
p = int(p_hex[2:], 16)
g = int(g_hex[2:], 16)
A = int(A_hex[2:], 16)
print("p: ", p)
print("g: ", g)
print("A: ", A)

# A = g*a mod p
a = A // g
print("a: ", a)

io.recvuntil(b'Intercepted from Bob: ')
bob = json.loads(io.recvline())
B_hex = bob['B']
B = int(B_hex[2:], 16)
print("B: ", B)
io.recvuntil(b'Intercepted from Alice: ')
alice2 = json.loads(io.recvline())
iv, enc_flag = bytes.fromhex(alice2['iv']), bytes.fromhex(alice2['encrypted'])
print("IV: ", iv)
print("Encrypted flag: ", enc_flag)

shared_secret = B * a % p
print("Shared secret: ", shared_secret)
sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(enc_flag)
print(plaintext.decode())