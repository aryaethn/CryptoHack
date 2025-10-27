

s = "label"
flag = ""   

for i in range(len(s)):
    flag += chr(ord(s[i]) ^ 13)
print(flag)