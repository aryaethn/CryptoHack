import json
from mpmath import mp
import binascii
import subprocess
import os
import binascii

mp.dps = 300
scale_bits = 400 
S = mp.mpf(1) * (1 << scale_bits)

with open('output_real_curve_crypto.txt', 'r') as f:
    data = json.load(f)

gx = mp.mpf(data['gx'])
px = mp.mpf(data['px'])

inv_y = lambda x: 1 / mp.sqrt(x**3 - x)
u_G = mp.quad(inv_y, [gx, mp.inf])
u_P = mp.quad(inv_y, [px, mp.inf])
omega = 2 * mp.quad(inv_y, [1, mp.inf])


val_uG = int(u_G * S)
val_omega = int(omega * S)
val_uP = int(u_P * S)

matrix = [
    [1, 0, 0, val_uG],
    [0, 1, 0, -val_omega], 
    [0, 0, 1, -val_uP]     
]

def lll_reduction(basis, delta=0.99):
    n = len(basis)
    
    def update_gram_schmidt(basis):
        ortho = []
        mu = [[mp.mpf(0)]*n for _ in range(n)]
        for i in range(n):
            b_mp = [mp.mpf(x) for x in basis[i]]
            b_star = list(b_mp)
            for j in range(i):
                dot_val = mp.fsum([b_mp[k] * ortho[j][k] for k in range(len(b_mp))])
                norm_sq = mp.fsum([x*x for x in ortho[j]])
                u_ij = dot_val / norm_sq
                mu[i][j] = u_ij
                for k in range(len(b_mp)):
                    b_star[k] -= u_ij * ortho[j][k]
            ortho.append(b_star)
        return ortho, mu

    ortho, mu = update_gram_schmidt(basis)
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = int(mp.nint(mu[k][j]))
                for i in range(len(basis[k])):
                    basis[k][i] -= q * basis[j][i]
                ortho, mu = update_gram_schmidt(basis)
        norm_sq_k = mp.fsum([x*x for x in ortho[k]])
        norm_sq_k_1 = mp.fsum([x*x for x in ortho[k-1]])
        if norm_sq_k >= (delta - mu[k][k-1]**2) * norm_sq_k_1:
            k += 1
        else:
            basis[k], basis[k-1] = basis[k-1], basis[k]
            ortho, mu = update_gram_schmidt(basis)
            k = max(k - 1, 1)
    return basis

reduced = lll_reduction(matrix)

print("Reduced Basis (first 3 cols):")
for r in reduced:
    print(r[:3])
    


possible_N = None
for row in reduced:
    if abs(row[2]) == 1:
        found_N = row[0]
        if row[2] == -1: 
             possible_N = found_N
        else: 
             possible_N = -found_N
        break

if possible_N:
    print(f"N: {possible_N}")
else:
    print("N not found")

N = 106141468078803597872809305192151622442


def long_to_bytes(n):
    h = hex(n)[2:]
    if len(h) % 2 != 0:
        h = '0' + h
    return binascii.unhexlify(h)

key = long_to_bytes(N)
print(f"Key hex: {key.hex()}")



key_hex = "4fda1a69712e64c3f8c19e78d7d3a32a"
iv_hex = "485f9a1e4a3b19348367280df13f9e77"
ciphertext_hex = "a104b68d30a207eabf293324fbde64f8d628fb07068058c1e76e670e7e805fc567f739185bbe6cbb44f09013173ee653"


with open('ct.bin', 'wb') as f:
    f.write(bytes.fromhex(ciphertext_hex))


cmd = [
    'openssl', 'enc', '-d', '-aes-128-cbc',
    '-K', key_hex,
    '-iv', iv_hex,
    '-in', 'ct.bin',
    '-out', 'pt.txt'
]

try:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        with open('pt.txt', 'rb') as f:
            print(f"Decrypted: {f.read()}")
    else:
        print(f"OpenSSL failed: {result.stderr}")
except Exception as e:
    print(f"Error: {e}")