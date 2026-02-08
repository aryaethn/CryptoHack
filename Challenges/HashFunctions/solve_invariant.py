from pwn import remote
import json

HOST, PORT = "socket.cryptohack.org", 13393

data = b"\x66" * 64  # 8 blocks, each block is 0x66 repeated

io = remote(HOST, PORT)
print(io.recvline().decode().strip())

io.sendline(json.dumps({
    "option": "hash",
    "data": data.hex()
}).encode())

print(io.recvline().decode().strip())
io.close()