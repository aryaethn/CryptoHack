from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from factordb.factordb import FactorDB


for i in range(1, 51):
    with open(f"keys_and_messages/{i}.pem", 'r') as f:
        key = RSA.importKey(f.read())
        # print(key.exportKey)
    with open(f"keys_and_messages/{i}.ciphertext", "r") as a:
        c = a.read() 
    try:
        f = FactorDB(key.n)
        f.connect()
        [p, q] = f.get_factor_list()
    except:
        continue
    phi= (p-1)*(q-1)
    d = pow(key.e, -1, phi)
    c = bytes.fromhex(c)
    print(c)
    key = RSA.construct((key.n, key.e, d))
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(c)
    print(plaintext)