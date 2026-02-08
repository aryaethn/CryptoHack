from pwn import *
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

from sage.all import *

# Connect to the challenge
r = remote('socket.cryptohack.org', 13408)

# 1. Receive Registration Data
r.recvuntil(b"New client is uploading crypto material...\n")
material = json.loads(r.recvline().decode())
master_key_enc = bytes.fromhex(material['master_key_enc'])
share_key_enc = bytes.fromhex(material['share_key_enc'])
N = material['share_key_pub'][0]
e = material['share_key_pub'][1]

print(f"[+] Received N: {N}")

# 2. Prepare Payload
# We pick a known message m (must be > 16 bytes to survive truncation logic slightly)
# We make it large enough to look like a real key/sid
known_m = b"A" * 32
known_m_int = bytes_to_long(known_m)
SID_enc_int = pow(known_m_int, e, N)
SID_enc = long_to_bytes(SID_enc_int)

# 3. Create Corrupted share_key_enc
# Structure: len(p)|p|len(q)|q...
# p is ~128 bytes. q starts around byte 132.
# AES block size is 16.
# Block 10 (bytes 160-176) is safely inside q.
# Let's corrupt block 10 by setting it to all 0s.
blocks = [share_key_enc[i:i+16] for i in range(0, len(share_key_enc), 16)]
blocks[10] = b'\x00' * 16
corrupted_share_key_enc = b"".join(blocks)

# 4. Interact with Server
# Switch to LOGIN state
r.sendline(json.dumps({"action": "wait_login"}).encode())

# Consumes "Login attempt from Alice..."
r.recvline() 

# FIX: Consume the JSON response {"auth_key_hashed": ...} that follows
r.recvline() 

# Now send the challenge with corrupted key
request = {
    "action": "send_challenge",
    "SID_enc": SID_enc.hex(),
    "share_key_enc": corrupted_share_key_enc.hex(),
    "master_key_enc": master_key_enc.hex()
}
r.sendline(json.dumps(request).encode())

# This will now correctly read the response to "send_challenge"
response = json.loads(r.recvline().decode())

if "error" in response:
    print("[-] Error:", response["error"])
    exit()

# Get the truncated decrypted SID (faulty decryption)
SID_faulty_hex = response['SID']
m_prime_trunc = bytes_to_long(bytes.fromhex(SID_faulty_hex))

print(f"[+] Got truncated faulty plaintext: {m_prime_trunc}")

# 5. Recover p using Coppersmith / GCD
# We know: (m_prime_trunc * 2^128 + x) - known_m = k * p
# Let A = m_prime_trunc * 2^128 - known_m
# We want root of A + x = 0 (mod p)

print("[*] Attempting to recover p with SageMath...")

# SageMath logic
R = Zmod(N)
P = PolynomialRing(R, 'x')
x = P.gen()
# The missing part is 16 bytes = 128 bits
diff = (m_prime_trunc * 2**128) - known_m_int
f = x + diff

# We are looking for a root modulo a divisor of N (which is p)
# Beta is approx size of p relative to N (0.5)
# We need x < N^(beta^2). N^0.25 is approx 512 bits. x is 128 bits.
# This should work easily.
roots = f.small_roots(beta=0.4, epsilon=0.01)

if not roots:
    print("[-] No roots found.")
    exit()

recovered_x = int(roots[0])
m_prime = (m_prime_trunc * 2**128) + recovered_x

# GCD step
p = gcd(m_prime - known_m_int, N)
print(f"[+] Recovered p: {p}")

# 6. Decrypt the Flag
q = N // p
assert p * q == N

# Reconstruct key derivation
secret = SHA256.new(long_to_bytes(p) + long_to_bytes(q)).digest()

# Get encrypted flag
r.sendline(json.dumps({"action": "get_encrypted_flag"}).encode())
flag_enc = bytes.fromhex(json.loads(r.recvline().decode())["encrypted_flag"])

# Decrypt
cipher = AES.new(secret, AES.MODE_ECB)
flag = unpad(cipher.decrypt(flag_enc), 16)

print(f"\n[SUCCESS] FLAG: {flag.decode()}")