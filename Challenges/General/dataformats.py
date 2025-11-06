from Crypto.PublicKey import RSA
from OpenSSL import crypto
import hashlib
import base64

key = RSA.import_key(open("privacy_enhanced_mail.pem", "rb").read())
# print("n: ", key.n)
# print("e: ", key.e)
# print("d: ", key.d)
# print("p: ", key.p)
# print("q: ", key.q)

# print()
key = RSA.import_key(open("2048b-rsa-example-cert.der", "rb").read())
# print("n: ", key.n)
# print("e: ", key.e)

# print()

ssh_pub_key = RSA.import_key(open("bruce_rsa.pem", "rb").read())
# print(ssh_pub_key.n)

# bash command for transparency challenge:
# openssl pkey -outform der -pubin -in transparency.pem | sha256sum
# Fingerprint: 29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2
# Search in https://crt.sh/ as SHA256 hash to find the certificate
