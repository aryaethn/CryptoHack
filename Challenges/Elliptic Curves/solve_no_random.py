import hashlib
from sage.all import *

# 1. Setup Constants (NIST P-256 / secp256r1 parameters)
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
# The curve used in the challenge (NIST P-256)
E = EllipticCurve(GF(p), [-3, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b])

# Hidden Flag Point T (from output.txt)
T_x = 16807196250009982482930925323199249441776811719221084165690521045921016398804
T_y = 72892323560996016030675756815328265928288098939353836408589138718802282948311
T = E(T_x, T_y)

# Signatures (from output.txt)
sigs = [
    {'msg': 'I have hidden the secret flag as a point of an elliptic curve using my private key.', 'r': 0x91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae, 's': 0x1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d},
    {'msg': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', 'r': 0xe8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c, 's': 0x582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8},
    {'msg': 'Good luck!', 'r': 0x566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6, 's': 0x9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba}
]

# 2. Calculate A_i and B_i
# Equation: k_i = A_i * d + B_i (mod order)
A = []
B = []
for s in sigs:
    # Hash the message using SHA1 as per source.py
    h = int(hashlib.sha1(s['msg'].encode()).hexdigest(), 16)
    s_inv = inverse_mod(s['s'], order)
    
    # A = s^-1 * r
    A.append((s_inv * s['r']) % order)
    # B = s^-1 * h
    B.append((s_inv * h) % order)

# 3. Construct the Lattice
# ... (Keep the imports and constants setup from before)

# ... (Keep the A and B calculation loop)

# --- RECENTERING ---
# Shift the target range from [0, 2^160] to [-2^159, 2^159]
# This makes the target vector shorter and easier for LLL to find.
bias = 2^159 
B_centered = [(b - bias) % order for b in B]

# 3. Construct the Lattice
# We use the centered B values here
K = order
L = Matrix(ZZ, [
    [order, 0, 0, 0],
    [0, order, 0, 0],
    [0, 0, order, 0],
    [A[0], A[1], A[2], 0],          
    [B_centered[0], B_centered[1], B_centered[2], K] 
])

# 4. Run LLL
L_red = L.BKZ(block_size=20)
print("First row of reduced lattice:", L_red[0])
print("Lattice reduced. Searching for solution...")

found_d = None
for row in L_red:
    # Check if the last element is +/- K
    if abs(row[-1]) == K:
        vec = row
        # Fix sign if necessary
        if row[-1] < 0:
            vec = -row
            
        # vec[0] corresponds to (k1 - bias)
        # So we add the bias back to get the real nonce k1
        k1_recovered = vec[0] + bias
        
        # Recover d: k1 = A1*d + B1  =>  d = (k1 - B1) * A1^-1
        # Note: Use the original B[0], not B_centered
        d_candidate = ((k1_recovered - B[0]) * inverse_mod(A[0], order)) % order
        
        # Check against the second signature to be sure
        # We compute what k2 SHOULD be with this d, and compare to what the vector gave us
        k2_derived = (A[1] * d_candidate + B[1]) % order
        k2_from_vec = vec[1] + bias # The vector stores (k2 - bias)
        
        # We compare them modulo order (just in case of boundary wraps, though rare here)
        if k2_derived == k2_from_vec:
            found_d = d_candidate
            break

# ... (Keep the flag printing logic)
if found_d:
    print(f"\nRecovered private key d: {found_d}")
    
    # 5. Recover the Flag
    # The problem states T = d * Q, so Q = d^-1 * T
    d_inv = inverse_mod(found_d, order)
    Q = d_inv * T
    
    # Convert x-coordinate to bytes
    from Crypto.Util.number import long_to_bytes
    flag = long_to_bytes(int(Q.xy()[0]))
    print(f"\n🚩 Flag found: {flag.decode()}")
else:
    print("Failed to find the key.")