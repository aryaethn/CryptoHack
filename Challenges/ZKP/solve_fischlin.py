import json
from hashlib import sha512

from pwn import remote
from Crypto.Util.number import bytes_to_long

HOST = "archive.cryptohack.org"
PORT = 3583

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

B = 6
NUM_ROUNDS = 64


def RO(a0, a1, e, e0, e1, z0, z1):
    h = sha512(b'my')
    h.update(str(a0).encode())
    h.update(b'very')
    h.update(str(a1).encode())
    h.update(b'cool')
    h.update(str(e).encode())
    h.update(b'random')
    h.update(str(e0).encode())
    h.update(b'oracle')
    h.update(str(e1).encode())
    h.update(b'for')
    h.update(str(z0).encode())
    h.update(b'fischlin')
    h.update(str(z1).encode())
    return bytes_to_long(h.digest())


def test_branch0_real(a0, a1, e, e0, e1, z0, z1, w0):
    """Hypothesis: branch0 was the real (non-simulated) leg, i.e. b==0.
    Under that hypothesis e1 is the fixed e_sim used throughout grinding,
    and r_b = z0 - e0*w0 (mod q) is the prover's committed randomness.
    Replay the grinding search for every e' < e under this hypothesis: if
    the server's real loop had used this exact (r_b, e_sim) pair, none of
    those e' could have satisfied the random-oracle condition (else the
    loop would have stopped earlier than e). Any hit falsifies b==0 with
    certainty -- meaning the actual answer is definitely b==1.
    """
    r_b = (z0 - e0 * w0) % q
    for ep in range(e):
        e0p = ep ^ e1
        z0p = (r_b + e0p * w0) % q
        if RO(a0, a1, ep, e0p, e1, z0p, z1) < 2**(512 - B):
            return False
    return True


def test_branch1_real(a0, a1, e, e0, e1, z0, z1, w1):
    r_b = (z1 - e1 * w1) % q
    for ep in range(e):
        e1p = ep ^ e0
        z1p = (r_b + e1p * w1) % q
        if RO(a0, a1, ep, e0, e1p, z0, z1p) < 2**(512 - B):
            return False
    return True


r = remote(HOST, PORT)

for round_i in range(NUM_ROUNDS):
    r.recvuntil(b"round:")
    r.recvline()
    r.recvline()

    attempt = 0
    guess = None
    while True:
        r.recvuntil(b"y0 = ")
        y0 = int(r.recvline().strip())
        r.recvuntil(b"y1 = ")
        y1 = int(r.recvline().strip())

        leak = attempt % 2
        r.sendlineafter(b"which witness do you want to see?", str(leak).encode())
        if leak:
            r.recvuntil(b"w1 = ")
            w1 = int(r.recvline().strip())
            w0 = None
        else:
            r.recvuntil(b"w0 = ")
            w0 = int(r.recvline().strip())
            w1 = None

        r.recvuntil(b"here is your fishlin transcript\n")
        proof = json.loads(r.recvline())
        a0, a1, e, e0, e1, z0, z1 = (proof["a0"], proof["a1"], proof["e"],
                                      proof["e0"], proof["e1"], proof["z0"], proof["z1"])

        if leak:
            consistent = test_branch1_real(a0, a1, e, e0, e1, z0, z1, w1)
            hyp_says = 1
        else:
            consistent = test_branch0_real(a0, a1, e, e0, e1, z0, z1, w0)
            hyp_says = 0

        commit = False
        if not consistent:
            guess = 1 - hyp_says
            commit = True
        else:
            confidence = 1 / (1 + (63 / 64) ** e)
            if confidence > 0.90 or attempt == 15:
                guess = hyp_says
                commit = True

        attempt += 1

        if commit:
            r.sendlineafter(b"do you think you can guess my witness? (y,n)", b"y")
            break
        else:
            r.sendlineafter(b"do you think you can guess my witness? (y,n)", b"n")

    r.sendlineafter(b"which witness did the prover use?", str(guess).encode())
    line = r.recvline().decode()
    print(f"round {round_i}: guess={guess} attempts_used={attempt} -> {line.strip()}")
    if "didn't guess" in line:
        print(r.recvall(timeout=3).decode())
        raise SystemExit("failed, rerun")

print(r.recvall(timeout=5).decode())
