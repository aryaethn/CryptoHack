#!/usr/bin/env python3

import socket
import json

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('socket.cryptohack.org', 13406))
welcome = s.recv(4096)

# Send command
cmd = {'option': 'encrypt_message', 'message': '00' * 16}
s.sendall(json.dumps(cmd).encode() + b'\n')
response = b''
while True:
    chunk = s.recv(4096)
    response += chunk
    if b'\n' in chunk:
        break

result = json.loads(response.decode())
enc_zero = result['encrypted_message']

# Get flag
cmd = {'option': 'encrypt_flag'}
s.sendall(json.dumps(cmd).encode() + b'\n')
response = b''
while True:
    chunk = s.recv(4096)
    response += chunk
    if b'\n' in chunk:
        break

result = json.loads(response.decode())
enc_flag = result['encrypted_flag']

s.close()

print(f"Encrypted zero: {enc_zero}")
print(f"Encrypted flag: {enc_flag}")

with open('beatbox_data.txt', 'w') as f:
    f.write(f"enc_zero = '{enc_zero}'\n")
    f.write(f"enc_flag = '{enc_flag}'\n")

print("\nData saved to beatbox_data.txt")
