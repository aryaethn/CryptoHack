from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import PKCS1_OAEP


f = open('key_fast_primes.pem','r')
key = RSA.import_key(f.read())
#Get the n and e value
n=key.n
e=key.e

print(f"n = {n}")
print(f"e = {e}")

# we used factordb.com to factorize n into p and q
p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
q = 77342270837753916396402614215980760127245056504361515489809293852222206596161

assert n == p * q

c = '249d72cd1d287b1a15a3881f2bff5788bc4bf62c789f2df44d88aae805b54c9a94b8944c0ba798f70062b66160fee312b98879f1dd5d17b33095feb3c5830d28'

phi = (p-1)*(q-1)
d = inverse(e, phi)
print(f"d = {d}")

assert e*d % phi == 1

key = RSA.construct((n, e, d))
print(f"public key = {key.publickey().export_key()}")
cipher = PKCS1_OAEP.new(key)
m = cipher.decrypt(bytes.fromhex(c))
print(f"m = {m}")
