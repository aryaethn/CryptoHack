import json

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13415

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

r = remote(HOST, PORT)
print(r.recvline().decode())

# set_internal_z computes self.z = inverse(poly(z_input, self.x), p) where
# poly(power, x) = x^(power+7) - x^3 (mod p). Choosing z_input = p - 5 makes
# the exponent power+4 = p-1, so by Fermat's little theorem x^(p-1) == 1
# (mod p) for ANY nonzero secret x -- poly(z_input, x) == 0 regardless of x.
# inverse(0, p) (the extended-Euclid implementation here) returns 0, so
# self.z becomes exactly 0 -- while the guard `(x*z) % p == 1` only checks
# mod p, never fires for z=0. With self.z=0, multiply(point, 0) is the
# point at infinity on both sides of the pairing check, and e(., O) == 1
# always -- so BLS() accepts ANY G/hsh we send.
z_input = p - 5
req = {"option": "set_internal_z", "z": hex(z_input)}
r.sendline(json.dumps(req).encode())
print(r.recvline().decode())

# G1 generator, in the (X,Y,Z) Jacobian form the server expects.
G1 = (1, 2, 1)
req = {"option": "do_proof", "G": f"({G1[0]},{G1[1]},{G1[2]})", "hsh": "1"}
r.sendline(json.dumps(req).encode())
print(r.recvline().decode())
