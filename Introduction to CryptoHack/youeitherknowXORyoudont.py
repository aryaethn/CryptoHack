h = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
b = bytes.fromhex(h)

secret = [b[0] ^ ord('c'), b[1] ^ ord('r'), b[2] ^ ord('y'), b[3] ^ ord('p'), b[4] ^ ord('t'), b[5] ^ ord('o'), b[6] ^ ord('{'), ord('y')]
print(len(b)%len(secret))
print(bytes(secret).decode())

flag = ""
for i in range(len(b)):
    flag += chr(b[i] ^ secret[i % len(secret)])
print(flag)