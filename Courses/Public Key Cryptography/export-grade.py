import pwn
import json
import hashlib
import random
from sympy.ntheory import discrete_log
from Crypto.Cipher import AES

host = "socket.cryptohack.org"
port = 13379


pr = pwn.connect(host, port)
try:
    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    supported_algorithms = line["supported"] # ['DH1536', 'DH1024', 'DH512', 'DH256', 'DH128', 'DH64']

    payload = json.dumps({"supported": ["DH64"]})
    print("To Bob: ", payload)
    pr.sendlineafter(": ", payload)


    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())

    payload = json.dumps({"chosen": "DH64"})
    print("To Alice: ", payload)
    pr.sendlineafter(": ", payload)
    

    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    p = int(line["p"], 16)
    g = int(line["g"], 16)
    A = int(line["A"], 16)

    print("p: ", p)
    print("g: ", g)
    print("A: ", A)

    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    B = int(line["B"], 16)
    print("B: ", B)
    
    pr.readuntil(": ")
    line = json.loads(pr.readline().strip().decode())
    iv = bytes.fromhex(line["iv"])
    ciphertext = bytes.fromhex(line["encrypted_flag"])
    
    #DLog is easy when p is small
    a = discrete_log(p, A, g)
    
    shared_secret = pow(B, a, p)
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    print("Plaintext: ", plaintext.decode())

    

    # pr.readuntil(": ")
    # line = json.loads(pr.readline().strip().decode())
    # print(line)
except Exception as e:
    print(e)
finally:
    pr.close()