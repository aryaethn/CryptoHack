"""
Bruce Schneier's Password -- the check() function validates the password
via `np.array(list(map(ord, password)))`, a fixed-width int64 numpy array.
`.sum()` stays comfortably within int64 range for any reasonable password,
but `.prod()` overflows almost immediately (ord values are ~50-120, so even
a dozen characters' product exceeds 2**63) and silently WRAPS AROUND modulo
2**64 (two's complement), exactly like C. The hint about 64-bit Linux is
pointing at this: the check isn't really testing whether the *true*
product is prime, only whether the wrapped-around int64 result happens to
be prime -- something we can search for directly.

Build a password '1' + 'A' + 'a'*k (one digit, one uppercase, k lowercase
'a's, satisfying \\w* and the digit/upper/lower requirements). Then:
  sum     = ord('1') + ord('A') + 97*k                       (exact)
  product = (ord('1') * ord('A') * 97**k) mod 2**64           (wrapped)
Both are simple functions of k; brute-force k until both are prime
(and the wrapped product stays < 2**63, i.e. positive as signed int64).

Note: ord('0') would make the product permanently even (hence never
prime) since 48 = 16*3 keeps a factor of 2 that survives the mod-2**64
wraparound forever -- '1' avoids that by keeping every factor odd.
"""
import json

from Crypto.Util.number import isPrime
from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13400

MOD = 2**64
DIGIT_ORD = ord('1')
UPPER_ORD = ord('A')
FILLER_ORD = ord('a')
FIXED_SUM = DIGIT_ORD + UPPER_ORD
FIXED_PROD = DIGIT_ORD * UPPER_ORD


def find_password():
    for k in range(1, 200000):
        s = FIXED_SUM + FILLER_ORD * k
        if not isPrime(s):
            continue
        p = (FIXED_PROD * pow(FILLER_ORD, k, MOD)) % MOD
        if p >= 2**63:
            continue  # would be negative as a signed int64
        if isPrime(p):
            return chr(DIGIT_ORD) + chr(UPPER_ORD) + chr(FILLER_ORD) * k
    raise RuntimeError("no password found in range")


password = find_password()
print(f"[+] password length {len(password)}")

r = remote(HOST, PORT)
r.recvline()
r.sendline(json.dumps({"password": password}).encode())
print(json.loads(r.recvline()))
r.close()
