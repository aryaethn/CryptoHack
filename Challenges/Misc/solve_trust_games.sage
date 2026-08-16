import json
from pwn import remote
from Crypto.Cipher import AES

HOST = "socket.cryptohack.org"
PORT = 13396

A_CONST = 0x1337deadbeef
B_CONST = 0xb
M_CONST = 2**48
SHIFT = 40          # 48 - 8
CHUNK = 1 << SHIFT  # 2**40

A_INV = int(pow(A_CONST, -1, M_CONST))


def next_state(state):
    return (A_CONST * state + B_CONST) % M_CONST


def prev_state(state):
    return ((state - B_CONST) * A_INV) % M_CONST


def recover_state1(known_bytes):
    """Given the top-8-bit outputs of 8 *consecutive* fresh LCG states
    (state_1..state_8, i.e. state_1 = next_state() applied once to a fresh,
    unknown 48-bit seed), recover state_1 exactly via a lattice (HNP) attack.
    """
    n = len(known_bytes)
    M = M_CONST

    A = [1] * n
    D = [0] * n
    for i in range(1, n):
        A[i] = (A[i - 1] * A_CONST) % M
        D[i] = (A_CONST * D[i - 1] + B_CONST) % M

    x0 = known_bytes[0] * CHUNK  # known top bits of state_1

    a_list = []
    alpha_list = []
    for i in range(1, n):
        Ai = A[i]
        Di = (A[i] * x0 + D[i]) % M
        target = (known_bytes[i] * CHUNK - Di) % M
        a_list.append(int(Ai))
        alpha_list.append(int(target))

    nsamp = len(a_list)
    B = matrix(ZZ, nsamp + 1, nsamp)
    for j in range(nsamp):
        B[j, j] = M
    for j in range(nsamp):
        B[nsamp, j] = a_list[j]

    # Approximate CVP via Babai's nearest-plane algorithm on an LLL-reduced
    # basis. (Sage's exact IntegerLattice.closest_vector() uses a Voronoi-cell
    # algorithm that is far too slow here.) Babai's rounding can occasionally
    # pick the wrong integer at a boundary, so we search a small neighborhood
    # of +-1 perturbations around each rounded coefficient and accept the
    # first candidate that reproduces every observed byte exactly.
    Breduced = B.LLL()
    rows = [vector(QQ, row) for row in Breduced.rows() if row != 0]
    bstar = []
    for b in rows:
        v = b
        for bs in bstar:
            v = v - (b.dot_product(bs) / bs.dot_product(bs)) * bs
        bstar.append(v)

    target_vec = vector(QQ, alpha_list)
    base_coeffs = []
    v = target_vec
    for i in reversed(range(len(rows))):
        c = round(v.dot_product(bstar[i]) / bstar[i].dot_product(bstar[i]))
        v = v - c * rows[i]
        base_coeffs.append(c)
    base_coeffs.reverse()  # now aligned with rows[0..], nearest-plane order was reversed

    def verify(state1):
        s = state1
        for i in range(n):
            if (s >> SHIFT) != known_bytes[i]:
                return False
            s = next_state(s)
        return True

    import itertools

    for deltas in itertools.product((0, 1, -1), repeat=len(rows)):
        v = target_vec
        for i in reversed(range(len(rows))):
            c = base_coeffs[i] + deltas[i]
            v = v - c * rows[i]
        cv = target_vec - v
        x = int((int(round(cv[0])) * pow(a_list[0], -1, M)) % M)
        if not (0 <= x < CHUNK):
            continue
        state1 = x0 + x
        if verify(state1):
            return state1

    raise ValueError("could not recover state1 -- lattice attack failed")


def bytes_to_states(b):
    return list(b)


r = remote(HOST, PORT)
banner = r.recvline().decode()
print(banner)

r.sendline(json.dumps({"option": "get_a_challenge"}).encode())
resp = json.loads(r.recvline())
print(resp)

plaintext = bytes.fromhex(resp["plaintext"])
IV = bytes.fromhex(resp["IV"])

# plaintext[8:16] == chainY positions 1..8 (fresh chain, key[0:8] == positions 9..16)
chainY_known = bytes_to_states(plaintext[8:16])
stateY_1 = recover_state1(chainY_known)

s = stateY_1
for _ in range(8):
    s = next_state(s)
key_first_half = bytearray()
for _ in range(8):
    key_first_half.append(s >> SHIFT)
    s = next_state(s)

# IV[0:8] == chainZ positions 9..16 (key[8:16] == positions 1..8 of the SAME chain,
# reached by walking the recovered state backwards)
chainZ_known = bytes_to_states(IV[0:8])
stateZ_9 = recover_state1(chainZ_known)

s = stateZ_9
for _ in range(8):
    s = prev_state(s)
# s is now chainZ's position 1 (== key[8]'s state); walk forward recording each byte
key_second_half = bytearray()
for _ in range(8):
    key_second_half.append(s >> SHIFT)
    s = next_state(s)

key = bytes(key_first_half) + bytes(key_second_half)
print("Recovered key:", key.hex())

cipher = AES.new(key, AES.MODE_CBC, IV)
ct = cipher.encrypt(plaintext)

r.sendline(json.dumps({"option": "validate", "ciphertext": ct.hex()}).encode())
final = json.loads(r.recvline())
print(final)

r.close()
