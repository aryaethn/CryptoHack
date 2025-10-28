p = 26513
q = 32321

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    else:
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y

g, x, y = extended_gcd(p, q)
print(g, x, y)