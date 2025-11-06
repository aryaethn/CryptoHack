from Crypto.Util.number import inverse

x_mod = [588,665,216,113,642,4,836,114,851,492,819,237]

for p in range(100, 1000):
    try:
        x1 = x_mod[1] * inverse(x_mod[0], p) % p
        x2 = x_mod[3] * inverse(x_mod[2], p) % p
        if x1 == x2:
            print(p, x1)
    except ValueError as e:
        pass
