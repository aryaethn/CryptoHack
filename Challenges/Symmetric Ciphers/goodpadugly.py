from pwn import *
import json

r = remote('socket.cryptohack.org', 13422)

def check_padding(previous, ciphertext):
    for i in range(23):
        ct = (previous + ciphertext).hex()
        r.sendline(json.dumps({"option": "unpad", "ct": ct}).encode())
        res = json.loads(r.recvline().decode())
        print(len(previous), previous, res)
        if not res['result']:
            return False
    return True

def attack(previous, ciphertext):
    possible_guess = b'0123456789abcdef'
    known_dct = bytearray(16)
    plaintext = bytearray(16)
    for i in range(15, -1, -1):
        pad_val = 16 - i
        for char in possible_guess:
            guess = char ^ pad_val ^ previous[i]
            prefix = bytes(i)
            middle = bytes([guess])
            suffix = bytes([known_dct[j] ^ pad_val for j in range(i + 1, 16)])
            fake_prev = prefix + middle + suffix
            if check_padding(fake_prev, ciphertext):
                known_dct[i] = guess ^ pad_val
                plaintext[i] = known_dct[i] ^ previous[i]
                print("FOUND", known_dct)
                break
    return bytes(plaintext)

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