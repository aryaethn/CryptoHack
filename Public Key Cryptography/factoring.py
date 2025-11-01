import math
from sympy.ntheory import factorint

N = 510143758735509025530880200653196460532653147

primes = factorint(N)

print(primes)