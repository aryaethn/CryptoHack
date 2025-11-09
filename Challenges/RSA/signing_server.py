import pwn
import json
from Crypto.Util.number import long_to_bytes

io = pwn.remote("socket.cryptohack.org", 13374)
io.recvline()

io.sendline(json.dumps({"option": "get_secret"}))
secret = json.loads(io.recvline())
c = int(secret["secret"], 16)

io.sendline(json.dumps({"option": "sign", "msg": hex(c)}))
signature = json.loads(io.recvline())
s = int(signature["signature"], 16)
print(long_to_bytes(s))