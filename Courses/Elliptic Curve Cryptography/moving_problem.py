from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def decrypt_flag(shared_secret: int, data: dict):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = bytes.fromhex(data['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = bytes.fromhex(data['encrypted_flag'])
    plaintext = cipher.decrypt(ciphertext)
    # plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext


G = (479691812266187139164535778017, 568535594075310466177352868412)
Alice_Public_Key = (1110072782478160369250829345256, 800079550745409318906383650948)
Bob_Public_Key = (1290982289093010194550717223760, 762857612860564354370535420319)
Data = {'iv': 'eac58c26203c04f68d63dc2c58d79aca', 'encrypted_flag': 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'}

# Since p is small, we used sage to extract private keys of Alice and Bob.
n_a = 29618469991922269 
n_b = 35442072047726594 

# Extract shared_key by n_b * Alice_Public_Key
shared_key = (57514367079882430785803122958, 54766665875029323535327747814)
# We can now decrypt the flag.
plaintext = decrypt_flag(shared_key[0], Data)
print(plaintext)

