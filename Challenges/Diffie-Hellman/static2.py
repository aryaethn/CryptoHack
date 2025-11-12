import pwn
import json
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from sympy.ntheory import discrete_log

host = "socket.cryptohack.org"
port = 13378

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def smooth_p():
    mul = 1
    i = 1
    while 1:
        mul *= i
        if (mul + 1).bit_length() >= p.bit_length() and isPrime(mul + 1):
            return mul + 1
        i += 1

io = pwn.remote(host, port)
io.recvuntil(b'Intercepted from Alice: ')
alice = json.loads(io.recvline())
p_hex, g_hex, A_hex = alice['p'], alice['g'], alice['A']
p = int(p_hex[2:], 16)
g = int(g_hex[2:], 16)
A = int(A_hex[2:], 16)
print("p: ", p)
print("g: ", g)
print("A: ", A)

io.recvuntil(b'Intercepted from Bob: ')
bob = json.loads(io.recvline())
B_hex = bob['B']
B = int(B_hex[2:], 16)
print("B: ", B_hex)

io.recvuntil(b'Intercepted from Alice: ')
alice2 = json.loads(io.recvline())
iv, enc_flag = bytes.fromhex(alice2['iv']), bytes.fromhex(alice2['encrypted'])
print("IV: ", iv)
print("Encrypted flag: ", enc_flag)

p_prime = smooth_p()
print("p_prime: ", p_prime)

io.recvuntil(b'send him some parameters: ')
to_bob={"p":hex(p_prime),"g":g_hex,"A":A_hex}
io.sendline(json.dumps(to_bob))
print("sent")

io.recvuntil(b'Bob says to you: ')
bob2 = json.loads(io.recvline())
B_hex2 = bob2['B']
B2 = int(B_hex2[2:], 16)
print("B2: ", B_hex2)
b = discrete_log(p_prime, B2, g)
print("b: ", b)

shared_secret = pow(A, b, p)
print("Shared secret: ", shared_secret)

sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(enc_flag)
if is_pkcs7_padded(plaintext):
    plaintext = unpad(plaintext, 16).decode()
else:
    plaintext = plaintext.decode()
print(plaintext)
