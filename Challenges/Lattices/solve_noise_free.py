#!/usr/bin/env python3
import json
import socket
import ast

HOST = "socket.cryptohack.org"
PORT = 13411

q = 0x10001  # 65537 (prime)
n = 64

def modinv(a, mod=q):
    return pow(a % mod, mod - 2, mod)  # Fermat since mod is prime

def dot_mod(A, S, mod=q):
    acc = 0
    for ai, si in zip(A, S):
        acc = (acc + (ai % mod) * (si % mod)) % mod
    return acc

class RREFSolver:
    """
    Incremental RREF builder for equations row·x = aug over GF(q).
    Maintains basis rows in reduced row echelon form.
    Once rank == n, solution is directly readable.
    """
    def __init__(self, n, mod):
        self.n = n
        self.mod = mod
        self.pivots = []   # pivot column index for each basis row
        self.rows = []     # basis rows (list of length n)
        self.augs = []     # corresponding augmented values

    def add_equation(self, row, aug):
        mod = self.mod
        row = [x % mod for x in row]
        aug %= mod

        # Eliminate existing pivots from this row
        for prow, pcol, paug in zip(self.rows, self.pivots, self.augs):
            coef = row[pcol]
            if coef:
                # row -= coef * prow
                for j in range(self.n):
                    row[j] = (row[j] - coef * prow[j]) % mod
                aug = (aug - coef * paug) % mod

        # Find pivot
        pivot = None
        for j, v in enumerate(row):
            if v % mod != 0:
                pivot = j
                break

        if pivot is None:
            # Either redundant (0=0) or inconsistent (0=nonzero)
            if aug % mod != 0:
                raise ValueError("Inconsistent system encountered (should not happen).")
            return False

        # Normalize pivot to 1
        inv = modinv(row[pivot], mod)
        for j in range(self.n):
            row[j] = (row[j] * inv) % mod
        aug = (aug * inv) % mod

        # Eliminate this pivot from all existing basis rows to keep RREF
        for i in range(len(self.rows)):
            coef = self.rows[i][pivot]
            if coef:
                for j in range(self.n):
                    self.rows[i][j] = (self.rows[i][j] - coef * row[j]) % mod
                self.augs[i] = (self.augs[i] - coef * aug) % mod

        # Add new basis row
        self.rows.append(row)
        self.augs.append(aug)
        self.pivots.append(pivot)
        return True

    @property
    def rank(self):
        return len(self.rows)

    def solution_if_full_rank(self):
        if self.rank != self.n:
            return None
        # In full rank RREF, we should effectively have x[pivot]=aug
        x = [0] * self.n
        for prow, pcol, paug in zip(self.rows, self.pivots, self.augs):
            x[pcol] = paug % self.mod
        return x

class CryptoHackSocket:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.f = self.s.makefile("rwb", buffering=0)

    def recv_json(self):
        line = self.f.readline()
        if not line:
            raise EOFError("Connection closed")
        return json.loads(line.decode())

    def send_json(self, obj):
        data = (json.dumps(obj) + "\n").encode()
        self.f.write(data)

def main():
    io = CryptoHackSocket(HOST, PORT)

    # Read banner/prompt (server usually sends a JSON)
    try:
        banner = io.recv_json()
        # print("Banner:", banner)
    except Exception:
        pass

    # 1) Recover S by querying encrypt(m=0) until we have rank 64
    solver = RREFSolver(n=n, mod=q)

    attempts = 0
    while solver.rank < n:
        attempts += 1
        io.send_json({"option": "encrypt", "message": 0})
        resp = io.recv_json()

        A = ast.literal_eval(resp["A"])
        b = int(resp["b"]) % q

        solver.add_equation(A, b)

        if attempts % 10 == 0:
            print(f"[+] equations tried: {attempts}, rank: {solver.rank}/{n}")

    S = solver.solution_if_full_rank()
    print("[+] Recovered S (secret vector).")

    # 2) Determine flag length safely (probe indices until error reveals max)
    flag_bytes = bytearray()

    idx = 0
    while True:
        io.send_json({"option": "get_flag", "index": idx})
        resp = io.recv_json()

        if "error" in resp:
            # Example: "index must be between 0 and X"
            print("[+] Server says:", resp["error"])
            break

        A = ast.literal_eval(resp["A"])
        b = int(resp["b"]) % q

        m = (b - dot_mod(A, S, q)) % q

        if m < 0 or m > 256:
            raise ValueError(f"Recovered plaintext out of byte range at idx={idx}: {m}")

        flag_bytes.append(m)
        idx += 1

    print("[+] Flag:", flag_bytes.decode(errors="replace"))

if __name__ == "__main__":
    main()
