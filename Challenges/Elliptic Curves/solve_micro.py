from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib



def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext


def Pohlig_Hellman(P, Q):
    n = P.order()
    factors = factor(n)
    results = []
    factors = []
    mul = 1
    for prime, exponent in factor(n):
        e = (n//(prime**exponent))
        P_new = e*P
        Q_new = e*Q
        dlog = P_new.discrete_log(Q_new)
        results.append(dlog)
        factors.append(prime**exponent)
        mul *= prime
        if mul > 1<<64:
            break
    return crt(results,factors)

def gen_shared_secret(P, n):
	S = n*P
	return S.xy()[0]

# Curve parameters
p = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a = 1
b = 4
E = EllipticCurve(GF(p), [a,b])
G = E(43190960452218023575787899214023014938926631792651638044680168600989609069200, 20971936269255296908588589778128791635639992476076894152303569022736123671173)
print("Generator point: ", G)

a_pub = ZZ(87360200456784002948566700858113190957688355783112995047798140117594305287669) # Alice's public key = (a_priv * G).x
A = E.lift_x(a_pub)
b_pub = ZZ(6082896373499126624029343293750138460137531774473450341235217699497602895121) # Bob's public key = (b_priv * G).x
B = E.lift_x(b_pub)
print("Alice's point: ", A)
print("Bob's point: ", B)

d_log = Pohlig_Hellman(G, A)
secret = gen_shared_secret(B, d_log)
print("secret: ", secret)
iv = bytes.fromhex('ceb34a8c174d77136455971f08641cc5')
encrypted_flag = bytes.fromhex('b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453')

plaintext = decrypt_flag(secret, iv,encrypted_flag)
print(plaintext)
