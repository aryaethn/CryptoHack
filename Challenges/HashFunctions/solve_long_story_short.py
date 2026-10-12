"""
Long Story Short -- the vault derives its AES key with
PBKDF2-HMAC-SHA256(passphrase, salt, 200000, 32), and publishes
sha256(passphrase).hexdigest() as a "fingerprint" for the operator to
sanity-check their typing. That fingerprint leaks the key.

HMAC's own spec is the culprit: if the key handed to HMAC is longer than
the underlying hash's block size (64 bytes for SHA-256), HMAC doesn't use
it directly -- it first replaces it with hash(key), *then* zero-pads that
to the block size. The passphrase here is 128 bytes, well over 64, so
every HMAC call PBKDF2 makes internally is already keyed on
sha256(passphrase) -- i.e. exactly the published fingerprint, not the
passphrase itself.

The fingerprint is only 32 bytes, under the 64-byte block size, so
feeding it back in as our own "passphrase" skips the hash-down step and
lands on the identical internal key (zero-padded the same way). HMAC, and
therefore PBKDF2, is then indistinguishable from the real run -- same
derived AES key, no need to ever know the real 128-character passphrase.
"""
import json

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13434

io = remote(HOST, PORT)
banner = json.loads(io.recvline())

io.sendline(json.dumps({"passphrase_hex": banner["passphrase_fingerprint"]}).encode())
print(json.loads(io.recvline())["msg"])
