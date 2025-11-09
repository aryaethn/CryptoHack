import pwn
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long
import re
from pkcs1 import emsa_pkcs1_v15

io = pwn.remote("socket.cryptohack.org", 13391)
io.recvline()

io.sendline(json.dumps({"option": "get_signature"}))
signature = json.loads(io.recvline())
N = int(signature["N"], 16)
E = int(signature["e"], 16)
SIGNATURE = int(signature["signature"], 16)

print("N= ", N)
print("E= ", E)
print("SIGNATURE= ", SIGNATURE)

msg = 'I am Mallory own CryptoHack.org'
digest = bytes_to_long(emsa_pkcs1_v15.encode(msg.encode(), 256))
print("digest= ", digest)
N = SIGNATURE - digest
print("N= ", N)
print(pow(SIGNATURE, int(1), N) == digest)
io.sendline(json.dumps({"option": "verify", "msg": "I am Mallory own CryptoHack.org", "N": hex(N), "e": hex(1)}))
print(io.recvline())