from pwn import *
import json

r = remote('socket.cryptohack.org', 13421)

def check_padding(iv, ciphertext):
    ct = (iv + ciphertext).hex()
    command = json.dumps({"option": "unpad", "ct": ct}).encode()
    r.sendline(command)
    res = json.loads(r.recvline().decode())
    print(len(iv), iv, res)
    return res['result']

def attack(iv, ciphertext):
    p = b''
    for i in range(16):
        padding = (i+1).to_bytes(1, 'big') * (i+1)
        for guess in range(256): 
            known_fake = xor(bytes([guess]) + p, padding)
            fake_iv = bytes(15 - i) + known_fake
            if check_padding(fake_iv, ciphertext):
                p = bytes([guess]) + p
                print("FOUND", p)
                break
    return xor(iv, p)

print(r.recvline().decode())
print()
getEncryptCommand = json.dumps({"option": "encrypt"}).encode()
r.sendline(getEncryptCommand)
ciphertext = r.recvline()
ciphertext = json.loads(ciphertext.decode())["ct"]
iv , ciphertext = bytes.fromhex(ciphertext)[:16], bytes.fromhex(ciphertext)[16:]
print(iv, ciphertext)

p = attack(iv, ciphertext[:16])
print(p)
p += attack(ciphertext[:16], ciphertext[-16:])
print(p)

decryptCommand = json.dumps({"option": "check", "message": p.decode()}).encode()
r.sendline(decryptCommand)

print(r.recvline().decode())