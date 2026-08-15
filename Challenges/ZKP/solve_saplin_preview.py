import ast
import json
from hashlib import sha256

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13414


def merge_nodes(a, b):
    return sha256(a + b).digest()


r = remote(HOST, PORT)
print(r.recvline().decode())

# request_checker() runs the credit check in a background Thread while
# challenge() checks self.balance_validated immediately after t.start() --
# a classic TOCTOU: self.balance_validated is still None (its just-reset
# default) at check time, and `None != False` is True, so the request is
# served regardless of whether we can actually afford it. A plain "0,8"
# request loses that race (the checker thread finishes near-instantly).
# Instead, ask for an absurdly large count: the checker thread's
# `for _ in range(wanted_nodes[layer])` loop then takes ages, guaranteeing
# our synchronous check runs first -- while the success path's
# `self.nodes[layer][:wanted_nodes[layer]]` slice just clamps to the real
# 8 leaves regardless of how large the requested count is.
req = json.dumps({"option": "get_nodes", "nodes": "0,100000000"}).encode()
r.sendline(req)
resp = json.loads(r.recvline())
print(resp)

nodes = ast.literal_eval(resp["msg"])
leaves = [bytes.fromhex(h) for h in nodes[0]]
assert len(leaves) == 8

layer1 = [merge_nodes(leaves[i], leaves[i + 1]) for i in range(0, 8, 2)]
layer2 = [merge_nodes(layer1[i], layer1[i + 1]) for i in range(0, 4, 2)]
root = merge_nodes(layer2[0], layer2[1])

req = {"option": "do_proof", "root": root.hex()}
r.sendline(json.dumps(req).encode())
resp = json.loads(r.recvline())
print(resp)
