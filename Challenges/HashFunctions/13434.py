#!/usr/bin/env python3

import hashlib
import json
import secrets
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utils import listener

FLAG = "crypto{????????????????????}"

KDF = "PBKDF2-HMAC-SHA256"
VAULT_SALT = b"bluerock-vault-2026"
ITERATIONS = 200000
KEY_BYTES = 32

MAX_PASSPHRASE_BYTES = 512

# Nobody types 128 characters of diceware correctly first time, so the vault
# publishes a fingerprint of the passphrase for the operator to check against.
PASSPHRASE_LENGTH = 128
PASSPHRASE_CHARSET = string.ascii_lowercase + "-"

OPERATOR_PASSPHRASE = "".join(
    secrets.choice(PASSPHRASE_CHARSET) for _ in range(PASSPHRASE_LENGTH)
).encode()

FINGERPRINT = hashlib.sha256(OPERATOR_PASSPHRASE).hexdigest()


def derive_key(passphrase):
    return hashlib.pbkdf2_hmac("sha256", passphrase, VAULT_SALT, ITERATIONS, KEY_BYTES)


def seal(plaintext, key):
    iv = secrets.token_bytes(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))


def open_vault(key):
    iv, ciphertext = VAULT[:16], VAULT[16:]
    try:
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
    except ValueError:
        return None


VAULT = seal(f"Recovery note -- {FLAG}".encode(), derive_key(OPERATOR_PASSPHRASE))


class Challenge():
    def __init__(self):
        self.before_input = json.dumps({
            "service": "Bluerock Vault",
            "kdf": KDF,
            "salt": VAULT_SALT.decode(),
            "iterations": ITERATIONS,
            "key_bytes": KEY_BYTES,
            "passphrase_length": PASSPHRASE_LENGTH,
            "passphrase_fingerprint": FINGERPRINT,
            "hint": "Send a passphrase or a passphrase_hex to unlock.",
        }) + "\n"

    def challenge(self, your_input):
        # Users may paste a passphrase, or supply raw bytes as hex.
        if "passphrase" in your_input:
            value = your_input["passphrase"]
            if not isinstance(value, str):
                return {"error": "passphrase must be a string."}
            passphrase = value.encode()
        elif "passphrase_hex" in your_input:
            value = your_input["passphrase_hex"]
            if not isinstance(value, str):
                return {"error": "passphrase_hex must be a string."}
            try:
                passphrase = bytes.fromhex(value)
            except ValueError:
                return {"error": "passphrase_hex must be valid hex."}
        else:
            return {"error": "Send a passphrase or a passphrase_hex."}

        if not passphrase:
            return {"error": "Passphrase must not be empty."}
        if len(passphrase) > MAX_PASSPHRASE_BYTES:
            return {"error": f"Passphrases are limited to {MAX_PASSPHRASE_BYTES} bytes."}

        contents = open_vault(derive_key(passphrase))
        if contents is None:
            return {"msg": "The vault did not open."}
        self.exit = True
        return {"msg": contents.decode()}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13434)
