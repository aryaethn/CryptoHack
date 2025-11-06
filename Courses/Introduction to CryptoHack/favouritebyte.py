h = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
b = bytes.fromhex(h)
print(b.decode())

secret = b[0] ^ ord('c')

flag = ""
for i in range(len(b)):
    flag += chr(b[i] ^ secret)
print(flag)