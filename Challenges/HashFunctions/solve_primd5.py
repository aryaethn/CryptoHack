#!/usr/bin/env python3
import json, pwn, hashlib
from Crypto.Util.number import isPrime

HOST = "socket.cryptohack.org"
PORT = 13392

def recv_line(sock) -> bytes:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recvline()
        if not chunk:
            break
        buf += chunk
    return buf

def recv_json(sock):
    line = recv_line(sock)
    if not line:
        return None
    return json.loads(line.decode())

def send_json(sock, obj):
    sock.sendline(json.dumps(obj).encode() + b"\n")

# --- Published MD5 single-block collision pair (64 bytes each) ---
# From Marc Stevens, "Single-block collision attack for MD5", Table 5.
m1 = bytes.fromhex(
    "4dc968ff0ee35c209572d4777b721587"
    "d36fa7b21bdc56b74a3dc0783e7b9518"
    "afbfa200a8284bf36e8e4b55b35f4275"
    "93d849676da0d1555d8360fb5f07fea2"
)
m2 = bytes.fromhex(
    "4dc968ff0ee35c209572d4777b721587"
    "d36fa7b21bdc56b74a3dc0783e7b9518"
    "afbfa202a8284bf36e8e4b55b35f4275"
    "93d849676da0d1d55d8360fb5f07fea2"
)

assert hashlib.md5(m1).digest() == hashlib.md5(m2).digest()

def find_suffix(a=101, suffix_len=8, limit=5_000_000):
    """
    Find s such that:
      p2 = int(m2||s) is divisible by a  (=> composite, since huge and a<p2)
      p1 = int(m1||s) is prime (<=1024 bits if total length <=128 bytes)
    """
    for ctr in range(limit):
        s = ctr.to_bytes(suffix_len, "big")
        M2 = m2 + s
        p2 = int.from_bytes(M2, "big")
        if p2 % a != 0:
            continue

        M1 = m1 + s
        p1 = int.from_bytes(M1, "big")
        # keep within server limit for signing primes
        if p1.bit_length() > 1024:
            continue
        if isPrime(p1):
            # sanity: collision still holds after suffix
            assert hashlib.md5(M1).digest() == hashlib.md5(M2).digest()
            return p1, p2, s, ctr
    raise RuntimeError("No suffix found; increase limit or tweak parameters.")

def main():
    a = 101  # choose an odd divisor >= len("crypto{...}") to leak whole flag

    p1, p2, s, ctr = find_suffix(a=a, suffix_len=8, limit=10_000_000)
    print(f"[+] Found suffix ctr={ctr}, suffix={s.hex()}")
    print(f"[+] p1 bits={p1.bit_length()} (prime), p2 bits={p2.bit_length()} (composite, divisible by {a})")

    with pwn.remote(HOST, PORT) as sock:
        banner = sock.recvline()
        if banner:
            print("[*] Banner:", banner)

        # 1) ask server to sign the prime p1
        send_json(sock, {"option": "sign", "prime": str(p1)})
        resp = recv_json(sock)
        if not resp or "signature" not in resp:
            raise RuntimeError(f"Sign failed: {resp}")
        sig = resp["signature"]
        print("[+] Got signature for p1.")

        # 2) reuse the signature for the composite p2 (same MD5 hash!)
        send_json(sock, {"option": "check", "prime": str(p2), "signature": sig, "a": str(a)})
        out = recv_json(sock)
        print("[+] Server response:", out)

if __name__ == "__main__":
    main()