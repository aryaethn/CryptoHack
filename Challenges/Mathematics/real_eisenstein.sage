from decimal import Decimal, getcontext
from math import floor

# Set precision for Decimal calculations
getcontext().prec = int(100)

# Prime numbers used in the encoding
prime_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103]

# The ciphertext value
ciphertext_value = 1350995397927355657956786955603012410260017344805998076702828160316695004588429433

# Scaling factor
scale = int(16**64)

# Number of characters in the flag
flag_length = 23

# Convert primes to integers
prime_integers = [int(p) for p in prime_list]

# Build the lattice matrix
dimension = flag_length + 1
lattice = Matrix(ZZ, dimension, dimension)

# Fill the matrix with identity and scaled square roots
for idx in range(flag_length):
    lattice[idx, idx] = 1
    lattice[idx, flag_length] = floor(Decimal(prime_integers[idx]).sqrt() * scale)

# Set the ciphertext in the bottom-right corner
lattice[flag_length, flag_length] = ciphertext_value

# Apply BKZ reduction to find the shortest vector
reduced_basis = lattice.BKZ()

# Extract the flag from the first row of the reduced basis
flag_string = ''.join(chr(abs(reduced_basis[0][j])) for j in range(flag_length))

print(flag_string)
