from scalar_multiplication import ecc_scalar_multiplication
from ecc_addition import ecc_add
import hashlib

O = 'inf'

a = 497
b = 1768
p = 9739

Q = (815,3190)
n = 1829
shared_secret = ecc_scalar_multiplication(Q, n, a, b, p)
# print(str(shared_secret))

sha1 = hashlib.sha1()
sha1.update(str(shared_secret[0]).encode())
key = sha1.hexdigest()

print(key)