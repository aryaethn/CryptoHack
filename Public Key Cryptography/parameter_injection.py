import pwn
import json
import hashlib
import random
from Crypto.Cipher import AES

host = "socket.cryptohack.org"
port = 13371


pr = pwn.connect(host, port)
try:
    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    p = int(line["p"], 16)
    g = int(line["g"], 16)
    A = int(line["A"], 16)
    
    print("From Alice:p: ", p, "g: ", g, "A: ", A)
    m = random.randint(1, p-1)
    M = pow(g, m, p)

    to_B = json.dumps({"p": hex(p), "g": hex(g), "A": hex(M)})
    print("To Bob: ", to_B)
    pr.sendlineafter(": ", to_B)
    
    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    B = int(line["B"], 16)
    print("From Bob: B: ", B)
    print(hex(M) < hex(B))

    to_A = json.dumps({"B": hex(M)})
    print("To Alice: ", to_A)
    pr.sendlineafter(": ", to_A)

    shared_secret_A = pow(A, m, p)
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret_A).encode('ascii'))
    keyA = sha1.digest()[:16]
    shared_secret_B = pow(B, m, p)
    sha1.update(str(shared_secret_B).encode('ascii'))
    keyB = sha1.digest()[:16]

    

    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    iv_alice = bytes.fromhex(line["iv"])
    ciphertext_alice = bytes.fromhex(line["encrypted_flag"])
    print("IV: ", iv_alice)
    print("Ciphertext: ", ciphertext_alice)
    cipher = AES.new(keyA, AES.MODE_CBC, iv_alice)
    plaintext_alice = cipher.decrypt(ciphertext_alice)
    print("From Alice: plaintext_alice: ", plaintext_alice)


except Exception as e:
    print(e)
finally:
    pr.close()