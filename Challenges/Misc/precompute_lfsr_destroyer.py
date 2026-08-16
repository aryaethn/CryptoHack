"""
LFSR Destroyer -- offline precomputation step (run once, ~4-5 minutes).

StreamCipher is a *filter generator*: a single 128-bit LFSR with public,
sparse feedback taps [0,1,2,7], whose output is 1 XOR F(x0..x5), where
x0..x5 are the register's bits at public positions [0,16,32,64,96,127] and F
is a fixed 6-input Boolean function of algebraic degree 5.

Because the register only shifts and appends (no other mixing), the exact
same "state_n[k] == u_{n+k}" sliding-window fact from the other LFSR
challenges holds here for a single underlying bit sequence u (u_0..u_127 ==
the 128-bit key). So x0..x5 at time n are each a *linear* function (a 128-bit
GF(2) mask) of the unknown key -- the nonlinearity is entirely inside F.

F has algebraic immunity 2: brute-forcing its 64-entry truth table finds a
degree-2 annihilator g of (F+1) -- i.e. g(x)=0 whenever output=1. Plugging
in the (linear) masks for x0..x5 turns "g(x)=0" into a *homogeneous
degree-2* equation in the 128 unknown key bits, for every keystream bit that
happens to be 1. With ~10000 such equations (out of up to 20000 available
keystream bits) against 8256 monomials (128 linear + C(128,2) quadratic),
the system is heavily overdetermined and solves to a 1-dimensional kernel:
the true key.

This script precomputes, for every possible keystream-bit position (up to
LIMIT*8 = 20000), the fully-expanded 8256-bit equation row implied by g --
independent of the actual (unknown) key, so the live/time-limited solve
script only has to pick out the rows where the observed bit was 1 and run
linear algebra.
"""
import itertools
import time

D = 128
TAPS_T = [0, 1, 2, 7]
TAPS_P = [0, 16, 32, 64, 96, 127]
WARMUP = 2 * D  # 256
LIMIT_BYTES = 2500
MAX_BITS = LIMIT_BYTES * 8

F_ANF = [[0, 1, 2, 3], [0, 1, 2, 4, 5], [0, 1, 2, 5], [0, 1, 2], [0, 1, 3, 4, 5], [0, 1, 3, 5], [0, 1, 3], [0, 1, 4], [0, 1, 5], [0, 2, 3, 4, 5], [
    0, 2, 3], [0, 3, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 5], [1, 2], [1, 3, 5], [1, 3], [1, 4], [1], [2, 4, 5], [2, 4], [2], [3, 4], [4, 5], [4], [5]]
N = 6


def find_annihilator():
    """Find a degree<=2 annihilator g of (F+1): g(x)=0 whenever F(x)=0
    (equivalently, whenever the keystream bit 1^F(x) equals 1)."""
    def evalF(x):
        v = 0
        for mono in F_ANF:
            p = 1
            for i in mono:
                p &= x[i]
            v ^= p
        return v

    inputs = list(itertools.product([0, 1], repeat=N))
    truth = [evalF(x) for x in inputs]

    monos = [()]
    monos += list(itertools.combinations(range(N), 1))
    monos += list(itertools.combinations(range(N), 2))
    nmono = len(monos)

    def eval_mono(mono, x):
        v = 1
        for i in mono:
            v &= x[i]
        return v

    rows = []
    for idx, x in enumerate(inputs):
        if truth[idx] == 0:
            row = 0
            for j, mono in enumerate(monos):
                if eval_mono(mono, x):
                    row |= (1 << j)
            rows.append(row)

    def rref(rows, nvars):
        rows = rows[:]
        pivots = []
        r = 0
        for col in range(nvars - 1, -1, -1):
            sel = None
            for i in range(r, len(rows)):
                if (rows[i] >> col) & 1:
                    sel = i
                    break
            if sel is None:
                continue
            rows[r], rows[sel] = rows[sel], rows[r]
            for i in range(len(rows)):
                if i != r and (rows[i] >> col) & 1:
                    rows[i] ^= rows[r]
            pivots.append(col)
            r += 1
            if r == len(rows):
                break
        return rows[:r], pivots

    reduced, pivots = rref(rows, nmono)
    free_cols = [c for c in range(nmono) if c not in pivots]
    assert len(free_cols) == 1, "expected a unique degree<=2 annihilator"
    f = free_cols[0]
    g = [0] * nmono
    g[f] = 1
    for row, pcol in zip(reduced, pivots):
        if (row >> f) & 1:
            g[pcol] = 1

    lin = [mono[0] for j, mono in enumerate(monos) if g[j] and len(mono) == 1]
    quad = [mono for j, mono in enumerate(monos) if g[j] and len(mono) == 2]
    return lin, quad


G_LIN, G_QUAD = find_annihilator()
print(f"[+] annihilator g: linear terms {G_LIN}, quadratic terms {G_QUAD}")

t0 = time.time()
state = [1 << k for k in range(D)]


def clock():
    global state
    newmask = state[TAPS_T[0]] ^ state[TAPS_T[1]] ^ state[TAPS_T[2]] ^ state[TAPS_T[3]]
    state = state[1:] + [newmask]


for _ in range(WARMUP):
    clock()
print(f"[+] warmup done in {time.time()-t0:.2f}s")

pair_index = {}
idx = D
for a in range(D):
    for b in range(a + 1, D):
        pair_index[(a, b)] = idx
        idx += 1
NCOLS = idx
print("total columns:", NCOLS)

rows = []
t1 = time.time()
for n in range(MAX_BITS):
    x = [state[p] for p in TAPS_P]
    clock()

    row = 0
    for v in G_LIN:
        row ^= x[v]
    for (i, j) in G_QUAD:
        mi, mj = x[i], x[j]
        m = mi
        while m:
            a = (m & -m).bit_length() - 1
            m &= m - 1
            mm = mj
            while mm:
                b = (mm & -mm).bit_length() - 1
                mm &= mm - 1
                if a == b:
                    row ^= (1 << a)
                else:
                    lo, hi = (a, b) if a < b else (b, a)
                    row ^= (1 << pair_index[(lo, hi)])
    rows.append(row)
    if (n + 1) % 2000 == 0:
        print(f"  built {n+1}/{MAX_BITS} rows, elapsed {time.time()-t1:.1f}s")

print(f"[+] all rows built in {time.time()-t1:.2f}s")

nbytes = (NCOLS + 7) // 8
with open("lfsr_destroyer_rows.bin", "wb") as f:
    f.write(NCOLS.to_bytes(4, "little"))
    f.write(len(rows).to_bytes(4, "little"))
    for r in rows:
        f.write(r.to_bytes(nbytes, "little"))

print(f"[+] saved lfsr_destroyer_rows.bin, total time {time.time()-t0:.2f}s")
