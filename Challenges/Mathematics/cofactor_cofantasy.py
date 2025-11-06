from Crypto.Util.number import *
from pwn import remote
import json
import time


r = remote('socket.cryptohack.org', 13398)
print(r.recvline().decode())

def measure_time(i):
    st = time.time()
    for _ in range(5):
        r.send(json.dumps({'option': 'get_bit', 'i': i}).encode())
        r.recvline()
    ed = time.time()
    return ed - st
high = measure_time(0)
low = measure_time(7)
mid = high - (high - low) * 0.618
print(high, low, mid)

flag = ''
num_now = ''
for i in range(8 * 43):
    num_now += '01'[measure_time(i) > mid]
    if i % 8 == 7:
        flag += chr(int(num_now[::-1], 2))
        num_now = ''
print(flag)