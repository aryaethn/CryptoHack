from pwn import remote
from json import dumps

Q = (0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A)

order = 115792089210356248762697446949407573529996955224135760342422259061068512044369 # Driven from sage.

io = remote("socket.cryptohack.org", 13382)
request = {"curve" : "nist256", "generator" : (int(Q[0]), int(Q[1])), "private_key" : order+1, "host" : "www.bing.com"}
request = dumps(request).encode()

io.sendlineafter(b"library!\n", request)
io.interactive()
