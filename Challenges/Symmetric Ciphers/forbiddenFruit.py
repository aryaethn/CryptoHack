from Crypto.Util.number import *
import struct
import requests
import json

class GF2_128:
    """Galois Field GF(2^128) with irreducible polynomial x^128 + x^7 + x^2 + x + 1"""
    # Irreducible polynomial: x^128 + x^7 + x^2 + x + 1 = 0x187 (in reduced form)
    MODULUS = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
    
    def __init__(self, value):
        self.value = value & ((1 << 128) - 1)  # Keep only 128 bits
    
    def __add__(self, other):
        # Addition in GF(2^128) is XOR
        return GF2_128(self.value ^ other.value)
    
    def __sub__(self, other):
        # Subtraction in GF(2^128) is also XOR
        return GF2_128(self.value ^ other.value)
    
    def __mul__(self, other):
        # Multiplication in GF(2^128)
        a = self.value
        b = other.value
        result = 0
        
        for i in range(128):
            if b & 1:
                result ^= a
            
            # Check if a needs reduction
            high_bit_set = a & (1 << 127)
            a <<= 1
            
            if high_bit_set:
                # Reduce by the irreducible polynomial (without the x^128 term)
                a ^= 0x87  # This is x^7 + x^2 + x + 1
            
            b >>= 1
        
        return GF2_128(result)
    
    def __truediv__(self, other):
        # Division is multiplication by the inverse
        return self * other.inverse()
    
    def inverse(self):
        # Extended Euclidean algorithm for GF(2^128)
        if self.value == 0:
            raise ZeroDivisionError("Cannot invert zero in GF(2^128)")
        
        # Use Fermat's little theorem: a^(2^128 - 2) = a^(-1) in GF(2^128)
        # Or use extended GCD
        return self._inv_euclid()
    
    def _inv_euclid(self):
        # Extended Euclidean algorithm in GF(2)[x]
        def gf2_poly_divmod(a, b):
            if b == 0:
                raise ZeroDivisionError()
            
            quotient = 0
            remainder = a
            
            b_degree = b.bit_length() - 1
            
            while remainder.bit_length() - 1 >= b_degree:
                shift = remainder.bit_length() - 1 - b_degree
                quotient ^= (1 << shift)
                remainder ^= (b << shift)
            
            return quotient, remainder
        
        r0, r1 = self.MODULUS, self.value
        s0, s1 = 0, 1
        
        while r1 != 0:
            q, r2 = gf2_poly_divmod(r0, r1)
            r0, r1 = r1, r2
            
            # Update s using polynomial multiplication in GF(2)
            s2 = s0
            # Multiply q * s1 in GF(2)[x] (without modulus)
            temp = 0
            q_temp = q
            s1_temp = s1
            for _ in range(256):  # More than enough iterations
                if q_temp & 1:
                    temp ^= s1_temp
                q_temp >>= 1
                s1_temp <<= 1
                if q_temp == 0:
                    break
            s2 ^= temp
            
            s0, s1 = s1, s2
        
        return GF2_128(s0)
    
    def __eq__(self, other):
        return self.value == other.value
    
    def __repr__(self):
        return f"GF2_128({hex(self.value)})"
    
    def integer_representation(self):
        return self.value

def polynomial_to_bytes(X):
    return int(f"{X.integer_representation():0128b}"[::-1], 2)

def bytes_to_polynomial(X):
    return GF2_128(int(f"{X:0128b}"[::-1], 2))

def ENCRYPT(plaintext):
    url = 'http://aes.cryptohack.org/forbidden_fruit/encrypt/'
    url += plaintext.hex()
    r = requests.get(url).json()
    if "error" in r:
        return None
    return  bytes.fromhex(r["nonce"]), bytes.fromhex(r["ciphertext"]), bytes.fromhex(r["tag"]), bytes.fromhex(r["associated_data"])

def DECRYPT(nonce, ciphertext, tag, associated_data):
    url = 'http://aes.cryptohack.org/forbidden_fruit/decrypt/'
    url += nonce.hex() + '/' + ciphertext.hex() + '/' + tag + '/' + associated_data.hex()
    r = requests.get(url).json()
    if "plaintext" in r:
        return bytes.fromhex(r["plaintext"])
    return None
payload = b"\x00"*16
nonce, c1, tag1, AD = ENCRYPT(payload)
payload = b"\x01"*16
_nonce, c2, tag2, _AD = ENCRYPT(payload)
c1 = bytes_to_polynomial(int.from_bytes(c1, 'big'))
c2 = bytes_to_polynomial(int.from_bytes(c2, 'big'))
tag1 = bytes_to_polynomial(int.from_bytes(tag1, 'big'))
tag2 = bytes_to_polynomial(int.from_bytes(tag2, 'big'))
print(f"{c1 = }\n")
print(f"{c2 = }\n")
print(f"{tag1 = }\n")
print(f"{tag2 = }\n")
    

H2= (tag1-tag2)/(c1-c2)
X = tag1 - c1*H2
assert X == tag2-c2*H2

ciphertext = requests.get("http://aes.cryptohack.org/forbidden_fruit/encrypt/" + (b"give me the flag").hex())
ciphertext = json.loads(ciphertext.text)
ciphertext = bytes.fromhex(ciphertext["ciphertext"])

tag = bytes_to_polynomial(int.from_bytes(ciphertext, 'big'))*H2 + X
tag = polynomial_to_bytes(tag)

print(f"{tag = }\n")
print(f"{nonce.hex() = }\n")
print(f"{AD.hex() = }\n")
print(DECRYPT(nonce, ciphertext, hex(tag)[2:], AD))
#Source: ldv
