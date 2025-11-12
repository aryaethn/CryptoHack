import random

P = 2
N = 50
E = 31337

FLAG = b'crypto{??????????????????????????}'

def bytes_to_binary(s):
    bin_str = ''.join(format(b, '08b') for b in s)
    bits = [int(c) for c in bin_str]
    return bits

def binary_to_bytes(mat, length):
    # mat is a matrix/list of lists (rows) of bits
    bits = []
    for row in mat:
        bits.extend(row)
    # Pack bits into bytes
    out = bytearray()
    for i in range(0, length, 8):
        byte = 0
        for j in range(8):
            if i + j < length:
                byte = (byte << 1) | int(bits[i + j])
        # Only append if there's at least 1 bit (i.e., full byte or final partial byte)
        out.append(byte)
    return bytes(out)

def generate_mat():
    while True:
        msg = bytes_to_binary(FLAG)
        msg += [random.randint(0, 1) for _ in range(N*N - len(msg))]

        rows = [msg[i::N] for i in range(N)]
        mat = Matrix(GF(2), rows)

        if mat.determinant() != 0 and mat.multiplicative_order() > 10^12:
            return mat

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

def save_matrix(M, fname):
    open(fname, 'w').write('\n'.join(''.join(str(x) for x in row) for row in M))

mat = generate_mat()

ciphertext = mat^E
save_matrix(ciphertext, 'flag.enc')



