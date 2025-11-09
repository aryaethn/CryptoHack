#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

FLAG = b"crypto{???????????????????????????????????}"


def pad100(msg):
    return msg + b'\x00' * (100 - len(msg))


key = RSA.generate(1024, e=3)
n, e = key.n, key.e

m = bytes_to_long(pad100(FLAG))
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")


# Based on the size of FLAG it has 57 bytes of \x00's.
# So we'll use sage with this information

msg = 836176173014351725787003135239010740549999681483399877452831888613352491590414136684
print(long_to_bytes(msg))