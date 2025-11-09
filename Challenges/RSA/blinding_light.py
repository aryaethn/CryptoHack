import pwn
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long
import re
from pkcs1 import emsa_pkcs1_v15

io = pwn.remote("socket.cryptohack.org", 13376)
io.recvline()

io.sendline(json.dumps({"option": "get_pubkey"}))
pubkey = json.loads(io.recvline())
N = int(pubkey["N"], 16)
E = int(pubkey["e"], 16)
print("N= ", N)
print("E= ", E)

msg = b"admin=True".hex()
sign = (pow(3, E)* int(msg, 16)) % N
print("sign= ", hex(sign))

io.sendline(json.dumps({"option": "sign", "msg": hex(sign)[2:]}))
signature = json.loads(io.recvline())


signature = int(signature["signature"], 16)
io.sendline(json.dumps({"option": "verify", "msg": msg,"signature": hex(signature* pow(3, -1, N) % N)[2:] }))
print(io.recvline())