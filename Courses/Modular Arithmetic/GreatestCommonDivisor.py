a = 66528
b = 52920

def gcd(a, b):
    while b!=0:
        a, b = b, a % b
    return a

print(gcd(a, b))