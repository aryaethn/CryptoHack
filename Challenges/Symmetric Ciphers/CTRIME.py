import requests
import json


url = "http://aes.cryptohack.org/ctrime/encrypt/"


flag = b"crypto{"

response = requests.get(url + flag.hex())
ciphertext = json.loads(response.content)["ciphertext"]
baseLength = len(ciphertext)

while 1:
	for i in range(32, 128):
		response = requests.get(url + flag.hex() + f"{hex(i)[2:]:0<2}")
		ciphertext = json.loads(response.content)["ciphertext"]
		if len(ciphertext) == baseLength:
			flag += bytes([i])
			print(flag)
			baseLength = len(ciphertext)
			if i == ord("}"):
				exit()
			break

		if i == 127:
			print("Failed to find another byte. Found flag: " + flag.decode())
			exit()

# After running the script, the flag is: crypto{CRIM
# It looks like it failed. Let's guess the next character.
# It is either E, e, or 3. This is based on the flag format of the CryptoHack challenges.
# Let's choose E, which is the same as the name of the challenge.
# Let's run the script again.