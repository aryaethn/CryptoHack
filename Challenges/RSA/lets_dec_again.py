#!/usr/bin/env sage

from sage.all import Mod, discrete_log
from pwn import remote
from json import dumps, loads
from Crypto.Util.number import bytes_to_long
from pkcs1 import emsa_pkcs1_v15

HOST, PORT = "socket.cryptohack.org", 13394
BIT_LENGTH = 768

def send_json(r, obj):
    r.sendline(dumps(obj).encode())
    return loads(r.recvline())

def encode_int(msg):
    return bytes_to_long(emsa_pkcs1_v15.encode(msg.encode(), BIT_LENGTH // 8))

# 1. connect + get signature
r = remote(HOST, PORT)
print(r.recvline().decode())

resp = send_json(r, {"option": "get_signature"})
S = int(resp["signature"], 16)

# 2. choose modulus n = p^k
p = 2010103
k = 50
n = p ** k

# 3. set_pubkey
resp = send_json(r, {"option": "set_pubkey", "pubkey": hex(n)})
suffix = resp["suffix"]

# 4. build messages
m0 = "This is a test message for a fake signature." + suffix
m1 = "My name is Arya and I own CryptoHack.org" + suffix
m2 = "Please send all my money to 3EovkHLK5kkAbE8Kpe53mkEbyQGjyf8ECw" + suffix

M0, M1, M2 = map(encode_int, (m0, m1, m2))

# 5. discrete logs in Z/nZ
S_mod  = Mod(S, n)
M0_mod = Mod(M0, n)
M1_mod = Mod(M1, n)
M2_mod = Mod(M2, n)

e0 = discrete_log(M0_mod, S_mod)
e1 = discrete_log(M1_mod, S_mod)
e2 = discrete_log(M2_mod, S_mod)

# sanity checks
assert pow(S, int(e0), n) == M0 % n
assert pow(S, int(e1), n) == M1 % n
assert pow(S, int(e2), n) == M2 % n

# 6. claim three secrets
sec0 = bytes.fromhex(send_json(r, {"option": "claim", "msg": m0, "index": 0, "e": hex(int(e0))})["secret"])
sec1 = bytes.fromhex(send_json(r, {"option": "claim", "msg": m1, "index": 1, "e": hex(int(e1))})["secret"])
sec2 = bytes.fromhex(send_json(r, {"option": "claim", "msg": m2, "index": 2, "e": hex(int(e2))})["secret"])

flag = bytes(a ^ b ^ c for a, b, c in zip(sec0, sec1, sec2))
print(flag.decode())