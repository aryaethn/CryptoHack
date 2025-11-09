import pwn
import json
from Crypto.Util.number import *


HOST = "socket.cryptohack.org"
PORT = 13386
print("Initializing connection to", HOST, PORT)

# If we find two encrypted messages that have the same modulus, we can crack the whole system. Let's do this.
lst_ns = []
lst_cs = []
lst_as = []
lst_bs = []
ct_count = None
r = pwn.remote(HOST, PORT)
r.recvline()
print("Got banner")
r.sendline(json.dumps({"option": "get_flag"}))
print("Sent get_flag")
obj = json.loads(r.recvline())
print("Got object")
c1 = obj["encrypted_flag"]
n1 = obj["modulus"]
(a1, b1) = obj["padding"]
print("c1= ", c1)
print("n1= ", n1)
print("a1= ", a1)
print("b1= ", b1)

r.sendline(json.dumps({"option": "get_flag"}))
print("Sent get_flag")
obj = json.loads(r.recvline())
print("Got object")
c2 = obj["encrypted_flag"]
n2 = obj["modulus"]
(a2, b2) = obj["padding"]
print("c2= ", c2)
print("n2= ", n2)
print("a2= ", a2)
print("b2= ", b2)

# From here we solve the problem with sage.

# m =
m = 754659823705280937426684693543545157731789888997963325308215810880829655843345426301
print(long_to_bytes(m))