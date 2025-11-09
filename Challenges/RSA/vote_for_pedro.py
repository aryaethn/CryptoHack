import pwn
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long
import re
from pkcs1 import emsa_pkcs1_v15

io = pwn.remote("socket.cryptohack.org", 13375)
io.recvline()

msg = bytes_to_long(b'VOTE FOR PEDRO')
print(msg)

# we used sage to find a signature 'sign' that sign ^ 3 = msg mod N

sign = '8a4c46bfb65e7eccc4e76a1ce2afc6f'

io.sendline(json.dumps({"option": "vote", "vote": sign}))
print(io.recvline())