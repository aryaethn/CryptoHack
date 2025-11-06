from Crypto.Util.number import bytes_to_long
from pwn import *
import json
from hashlib import sha1
from ecdsa.ecdsa import Public_key, Private_key, Signature, generator_192

io = remote("socket.cryptohack.org", 13381)
input = {"option" : "sign_time"}
input = json.dumps(input)

lst = {}

io.recvuntil(b"verify.\n")
while True:
    try:
        io.sendline(input.encode())
        sig = eval(io.recvline())
        
        print(sig)
        
        if sig["r"] not in lst:
            lst[sig["r"]] = sig
        else:
            tup1 = lst[sig["r"]]
            tup2 = sig
            break
    except:
        continue

g = generator_192
p = g.order()

z1 = bytes_to_long(sha1(str(tup1["msg"]).encode()).digest())
z2 = bytes_to_long(sha1(str(tup2["msg"]).encode()).digest())

r = int(tup1["r"], 16)
s1 = int(tup1["s"], 16)
s2 = int(tup2["s"], 16)

k = ((z1 - z2) * pow(s1 - s2, -1, p)) % p
d = ((s1 * k - z1) * pow(r, -1, p)) % p

msg = b"unlock"
hsh = sha1(msg).digest()

pubkey = Public_key(g, g * d)
privkey = Private_key(pubkey, d)

sig = privkey.sign(bytes_to_long(hsh), k)

packet = {"option" : "verify", "r" : hex(sig.r), "s" : hex(sig.s), "msg" : "unlock"}
packet = json.dumps(packet)

io.sendline(packet.encode())
io.interactive()
