from scalar_multiplication import ecc_scalar_multiplication
from decrypt import decrypt_flag

def find_y(y2, p):
    for i in range(p):
        if pow(i, 2, p) == y2:
            return (i, p-i)
    return None


p = 9739
a = 497
b = 1768

G = (1804,5368)

n_b = 6534
Q_A_x = 4726

y2 = pow(Q_A_x, 3, p) + a * Q_A_x % p + b % p
y = find_y(y2, p)
print(y)

Q_A1 = (Q_A_x, y[0])
Q_A2 = (Q_A_x, y[1])
shared_secret = ecc_scalar_multiplication(Q_A1, n_b, a, b, p)
shared_secret2 = ecc_scalar_multiplication(Q_A2, n_b, a, b, p)
print(shared_secret)
print(shared_secret2)

ciphertext = "febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8"
iv = "cd9da9f1c60925922377ea952afc212c"

try:
    print(decrypt_flag(shared_secret[0], iv, ciphertext))
except:
    print(decrypt_flag(shared_secret2[0], iv, ciphertext))