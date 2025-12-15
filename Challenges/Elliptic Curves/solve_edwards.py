from Crypto.Util.number import inverse, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha1
from sympy.ntheory import factorint
from sympy.ntheory.modular import crt
from sympy.ntheory.residue_ntheory import discrete_log

p = 110791754886372871786646216601736686131457908663834453133932404548926481065303
d_code = 14053231445764110580607042223819107680391416143200240368020924470807783733946
y0 = 11

alice_pub_y = 109790246752332785586117900442206937983841168568097606235725839233151034058387
bob_pub_y = 45290526009220141417047094490842138744068991614521518736097631206718264930032

encrypted_data = {
    'iv': '31068e75b880bece9686243fa4dc67d0', 
    'encrypted_flag': 'e2ef82f2cde7d44e9f9810b34acc885891dad8118c1d9a07801639be0629b186dc8a192529703b2c947c20c4fe5ff2c8'
}

def solve():
    print("[*] Analyzing curve parameters...")
    
    lhs = (-1**2 + 11**2) % p
    rhs = (1 + d_code * 1**2 * 11**2) % p
    
    if lhs != rhs:
        print("[!] Parameter mismatch confirmed: Base point is invalid.")
        print("[!] recover_x likely returns 0, forcing operations into Fp* (Degenerate Curve).")
    
    
    print("[*] Factoring p - 1...")
    
    factors = factorint(order)
    print(f"[*] Factors of p-1: {factors}")

    print("[*] Solving Discrete Logarithm (Pohlig-Hellman)...")
    
    remainders = []
    moduli = []
    
    for prime, exponent in factors.items():
        
        e = ((p-1)//(prime**exponent))
        print("Round's prime: ", prime, "Reound's e: ", e)
        alice_pub_y_new = pow(alice_pub_y, e, p)
        y0_new = pow(y0, e, p)
        print("Round's y0: ", y0_new, "Round's Alice Pub: ", alice_pub_y_new)
        dlog = discrete_log(p, alice_pub_y_new, y0_new, order = prime**exponent)
        print("Round's dlog: ", dlog)
        remainders.append(dlog)
        moduli.append(prime**exponent)
    
    n_a = crt(moduli, remainders)[0]
    print(f"[*] Recovered Alice's Private Key n_a: {n_a}")

    shared_secret = pow(bob_pub_y, n_a, p)
    print(f"[*] Shared Secret: {shared_secret}")

    print("[*] Decrypting Flag...")
    key = sha1(str(shared_secret).encode('ascii')).digest()[:16]
    iv = bytes.fromhex(encrypted_data['iv'])
    ciphertext = bytes.fromhex(encrypted_data['encrypted_flag'])
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    try:
        flag = unpad(plaintext, 16).decode()
        print(f"\n[SUCCESS] Flag: {flag}")
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")

solve()