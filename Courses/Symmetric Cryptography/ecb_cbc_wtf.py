from Crypto.Cipher import AES
from pwn import xor
import requests

def encrypt():
    url = "http://aes.cryptohack.org//ecbcbcwtf/encrypt_flag/"
    response = requests.get(url)
    return response.json()['ciphertext']

def decrypt(data):
    url = "http://aes.cryptohack.org//ecbcbcwtf/decrypt/"
    response = requests.get(url + data + '/')
    return response.json()['plaintext']

ciphertext = encrypt()
print("ciphertext: ", ciphertext)
blocks = []
for i in [0,32,64]:
    blocks.append(ciphertext[i:i+32])
print("blocks (before): ", blocks)
vi = blocks[0:(len(blocks)-1)]
blocks = blocks[1:]
print("blocks (after): ", blocks)

for i in range(len(blocks)):
    blocks[i] = decrypt(blocks[i])
print("blocks (after decrypt): ", blocks)


for i in range(len(blocks)):
    blocks[i] = xor(bytes.fromhex(blocks[i]),bytes.fromhex(vi[i]))
    
print("blocks (after xor): ", blocks)

flag = ""
for i in blocks:
    flag += i.decode()

print("flag: ", flag)
