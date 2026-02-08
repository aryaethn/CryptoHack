import ast
from hashlib import sha256

def h(x: bytes) -> bytes:
    return sha256(x).digest()

def merge(a: bytes, b: bytes) -> bytes:
    return h(a + b)

bits = []

with open("output_merkle_tree.txt", "r") as f:
    for line in f:
        a, b, c, d, root = ast.literal_eval(line.strip())
        a = bytes.fromhex(a)
        b = bytes.fromhex(b)
        c = bytes.fromhex(c)
        d = bytes.fromhex(d)
        root = bytes.fromhex(root)

        calc_root = merge(merge(a, b), merge(c, d))
        bits.append("1" if calc_root == root else "0")

bitstr = "".join(bits)

# pad on the LEFT to full bytes (generator drops leading zeros)
pad = (-len(bitstr)) % 8
bitstr = ("0" * pad) + bitstr

flag_bytes = bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8))
print(flag_bytes.decode())