from sage.all import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import json

# --- Part 1: Load All Challenge Data ---

# P from matrix_reloaded.sage [Source: 3]
P = 13322168333598193507807385110954579994440518298037390249219367653433362879385570348589112466639563190026187881314341273227495066439490025867330585397455471
N = 30
F = GF(P)

print("[+] Loading data...")

# Load generator.txt [Source: 5]
with open('generator.txt', 'r') as f:
    data = f.read().strip()
    rows = [list(map(int, row.split(' '))) for row in data.splitlines()]
    G = Matrix(F, rows)

# Load output.txt [Source: 1]
with open('output.txt', 'r') as f:
    output = json.load(f)
    v_list = output['v']
    w_list = output['w']
    v = vector(F, v_list)
    w = vector(F, w_list)

# Load flag.enc [Source: 2]
with open('flag.enc', 'r') as f:
    enc_data = json.load(f)
    iv_hex = enc_data['iv']
    ciphertext_hex = enc_data['ciphertext']

print("[+] All data loaded.")

# --- Part 2: Solve using Jordan Normal Form ---

print("[+] Finding Jordan Normal Form (J, S) of G...")
# This is the correct function for non-diagonalizable matrices
J, S = G.jordan_form(transformation=True)
print("[+] Found J and S. Inverting S...")

# This S should be invertible
S_inv = S.inverse()

print("[+] Transforming vectors v and w...")
v_prime = S_inv * v
w_prime = S_inv * w

print("[+] Searching for a 2x2 Jordan block...")

SECRET = 0
for i in range(N - 1):
    # A Jordan block of size >= 2 has a '1' on the super-diagonal
    if J[i, i+1] == 1:
        print(f"[i] Found Jordan block at index {i}")
        
        # Check that eigenvalues are the same
        if J[i, i] != J[i+1, i+1]:
            print(f"[!] Mismatch in block, skipping...")
            continue
            
        # Get components from our 2x2 block
        # w_i   = (lambda^x * v_i) + (x * lambda^(x-1) * v_{i+1})
        # w_{i+1} = (lambda^x * v_{i+1})
        
        lambda_val = J[i, i]
        v_i = v_prime[i]
        v_i_plus_1 = v_prime[i+1]
        w_i = w_prime[i]
        w_i_plus_1 = w_prime[i+1]
        
        # We must have v_{i+1} != 0 to solve
        if v_i_plus_1 == 0:
            print(f"[!] v'[{i+1}] is zero, cannot solve. Trying next block...")
            continue
            
        # 1. Solve for lambda^x from the second equation
        lambda_x = w_i_plus_1 / v_i_plus_1
        
        # 2. Substitute into the first equation and solve for x
        # x * lambda^(x-1) * v_{i+1} = w_i - (lambda^x * v_i)
        # x * (lambda_x * lambda_inv) * v_{i+1} = w_i - (lambda_x * v_i)
        
        A = w_i - (lambda_x * v_i)
        B = lambda_x * lambda_val.inverse() * v_i_plus_1
        
        if B == 0:
            print(f"[!] Denominator is zero, cannot solve. Trying next block...")
            continue
            
        # We found it!
        SECRET = A / B
        
        print(f"\n[+] SUCCESS! SECRET = {SECRET}")
        break

# --- Part 3: Decrypt the Flag ---
if SECRET == 0:
    print("\n[-] Attack failed. No suitable Jordan block found.")
else:
    print("\n[+] Deriving key and decrypting flag...")
    
    # Get the 32-byte (256-bit) AES key
    KEY = SHA256.new(data=str(SECRET).encode()).digest()
    
    # Convert hex IV and ciphertext to bytes
    iv_bytes = bytes.fromhex(iv_hex)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    
    # Set up the AES cipher
    cipher = AES.new(KEY, AES.MODE_CBC, iv_bytes)
    
    # Decrypt and unpad
    try:
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), 16)
        print("\n========================================")
        print(f"    FLAG: {plaintext.decode()}")
        print("========================================")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")