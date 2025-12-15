import json
import numpy as np
from Crypto.Util.number import long_to_bytes

collected_data = []
with open('collected_double_broken.txt', 'r') as f:
    data = f.read()
    collected_data = json.loads(data)

avg_leak = [0 for _ in range(len(collected_data[0]))]
for i in range(50):
    avg_leak = np.add(avg_leak, collected_data[i])
for i in range(len(avg_leak)):
    avg_leak[i] /= 50

bits = ""
for i in avg_leak:
    if i > 125:
        bits += "1"
    else: bits+="0"

bits+="0"
bits = bits[::-1]

d = int(bits, 2)


print(long_to_bytes(d))
