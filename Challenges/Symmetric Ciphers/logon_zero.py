from pwn import * # pip install pwntools
import json



url = ("socket.cryptohack.org", 13399)
conn = remote(url[0], url[1])

print(conn.recvline().decode())

token = b"\x00" * 28
resetPasswordCommand = json.dumps({"option": "reset_password", "token": token.hex()}).encode()
authCommand = json.dumps({"option": "authenticate", "password": ""}).encode()
resetCommand = json.dumps({"option": "reset_connection"}).encode()

while True:

	conn.sendline(resetPasswordCommand)
	conn.recvline().decode()

	conn.sendline(authCommand)
	ans = conn.recvline().decode()
	if "crypto{" in ans:
		print(ans)
		conn.close()
		exit(0)

	conn.sendline(resetCommand)
	conn.recvline().decode()