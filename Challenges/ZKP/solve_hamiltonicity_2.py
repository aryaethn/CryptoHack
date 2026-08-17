#!/usr/bin/env python3
"""
CryptoHack -- ZKP -- "Hamiltonicity 2"   (server source: chal.py)

Blum's ZK proof of Hamiltonicity, Fiat-Shamir'd, over a graph G that has NO
Hamiltonian cycle.  Goal: produce an accepting non-interactive proof.

---------------------------------------------------------------------------
Why the Hamiltonicity 1 attack does not work here
---------------------------------------------------------------------------
In Hamiltonicity 1 the challenge bit of round i was derived immediately from
the state after absorbing A_i, so a cheating prover could re-randomise A_i
until the bit came out as 1 -- two tries per round, 128 rounds, done.

Hamiltonicity 2 collects ALL 128 first messages first, then hashes them into
one state, then slices all 128 challenge bits out of that single digest:

    for i in range(numrounds):
        FS_state = hash_committed_graph(A_vals[i], FS_state, comm_params)
    challenge_bits = bin(int.from_bytes(FS_state, 'big'))[-numrounds:]

Now every bit depends on every A_j, so grinding a strategy vector into place
costs 2^128.  And the two branches genuinely cannot be answered by one first
message: challenge 0 opens all N^2 cells and compares them against a permuted
G, challenge 1 opens N cells of a Hamiltonian cycle to 1.  A single committed
matrix satisfying both would be a permuted G containing a Hamiltonian cycle.
(Not even a non-injective "permutation" helps -- permute_graph is unvalidated,
but a cheating cycle would need a closed 5-walk in G, and G is a 3-cycle plus
a disjoint 2-cycle, so A_G^5 has zero diagonal.)  Pedersen equivocation is out
too: P = 2q+1 is a 1024-bit safe prime, so the commitments really are binding.

---------------------------------------------------------------------------
The actual flaw: the Fiat-Shamir transcript encoding is ambiguous
---------------------------------------------------------------------------
The first message is absorbed as

    first_message = "".join([str(x) for xs in G for x in xs])

-- 25 cells concatenated with NO separator and NO type tag, and check_graph()
only ever checks that the matrix is 5x5.  So the string the hash sees does not
determine the matrix: any re-cut of the same digit string into 25 cells is a
different first message with an identical transcript contribution.  JSON lets
us send cells as strings, and str("...") is the bare content, so cells can
absorb arbitrary digits or be empty.

That breaks the binding between the challenge and the message it is supposed
to commit to.  For each round we build TWO first messages that hash to the
same string:

  A0 : an honest commitment to G (25 integer cells).  Answers challenge 0 --
       open everything, permutation = identity.

  A1 : the same digit string re-cut so that the five cells committing to G's
       edges land instead on the five positions of the Hamiltonian cycle
       0 -> 1 -> 3 -> 2 -> 4 -> 0.  Answers challenge 1 -- those five cells
       are commitments to 1 and we know their randomness.  The other 20 cells
       are strings holding the leftover digits (or empty) and are never opened
       on this branch.

Concretely, with the identity permutation G's edges sit at flat indices
[2, 5, 11, 19, 23] and the chosen cycle's edges sit at [1, 8, 14, 17, 20].
Both are increasing, and consecutive cycle slots differ by >= 2, so every gap
has at least one spare cell to park the intervening digits in.

Since A0 and A1 are transcript-identical, the challenge bits do not depend on
which one we will send.  So: compute all 128 bits offline first, then send the
matching variant in every round.  No grinding, no luck, succeeds first try.
"""

import json
import os
import sys

from hamiltonicity import comm_params, pedersen_commit, hash_committed_graph

N = 5
NUMROUNDS = 128

# the server's graph: 0->2->1->0 and 3->4->3.  No Hamiltonian cycle.
G = [
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0],
]

# Hamiltonian cycle we will "open" on the challenge-1 branch, as a walk.
# Edge flat indices 5*s+d are [1, 8, 17, 14, 20] -> sorted [1, 8, 14, 17, 20],
# pairwise non-adjacent, so each gap keeps a spare cell for leftover digits.
CYCLE = [[0, 1], [1, 3], [3, 2], [2, 4], [4, 0]]
PERM = [0, 1, 2, 3, 4]


def build_round():
    """One round: two transcript-identical first messages, with their answers."""
    # ---- A0: honest commitment to permute_graph(G, identity) = G ----------
    flat, open0 = [], []
    for i in range(N):
        for j in range(N):
            m = G[i][j]
            c, r = pedersen_commit(m)
            flat.append(c)
            open0.append([m, r])

    A0 = [flat[i * N:(i + 1) * N] for i in range(N)]
    z0 = [PERM, [open0[i * N:(i + 1) * N] for i in range(N)]]

    # ---- A1: same digit string, cells re-cut onto the cycle positions -----
    src = [t for t in range(N * N) if G[t // N][t % N] == 1]     # [2,5,11,19,23]
    dst = sorted(5 * s + d for s, d in CYCLE)                    # [1,8,14,17,20]
    assert len(src) == len(dst) == N
    assert all(dst[k + 1] - dst[k] >= 2 for k in range(N - 1))

    cells = [""] * (N * N)
    cells[0] = "".join(str(flat[t]) for t in range(0, src[0]))   # leading digits
    for k in range(N):
        cells[dst[k]] = flat[src[k]]                             # int, openable
        lo = src[k] + 1
        hi = src[k + 1] if k + 1 < N else N * N                  # digits in between
        cells[dst[k] + 1] = "".join(str(flat[t]) for t in range(lo, hi))

    A1 = [cells[i * N:(i + 1) * N] for i in range(N)]
    # randomness for each cycle edge, in the order testcycle() walks them
    pos_to_r = {dst[k]: open0[src[k]][1] for k in range(N)}
    z1 = [CYCLE, [pos_to_r[5 * s + d] for s, d in CYCLE]]

    # transcript contributions must be byte-identical
    def transcript(A):
        return "".join(str(x) for row in A for x in row)
    assert transcript(A0) == transcript(A1)

    return (A0, z0), (A1, z1)


def build_proof():
    rounds = [build_round() for _ in range(NUMROUNDS)]

    # the challenge depends only on the (shared) transcript, so we can derive
    # all 128 bits before deciding which variant to send
    state = b""
    for (A0, _), _ in rounds:
        state = hash_committed_graph(A0, state, comm_params)
    bits = bin(int.from_bytes(state, "big"))[-NUMROUNDS:]
    assert len(bits) == NUMROUNDS and set(bits) <= {"0", "1"}, "unlucky digest"

    payloads = []
    for i, (v0, v1) in enumerate(rounds):
        A, z = v1 if int(bits[i]) else v0
        payloads.append(json.dumps({"A": A, "z": z}))
    return payloads, bits


def main():
    payloads, bits = build_proof()
    print("[*] challenge bits: %s...%s (%d ones)"
          % (bits[:32], bits[-16:], bits.count("1")), file=sys.stderr)

    if "--emit" in sys.argv:
        print("\n".join(payloads))
        return

    host, port = os.environ.get("HAM2_HOST"), os.environ.get("HAM2_PORT")
    if not (host and port):
        print("set HAM2_HOST / HAM2_PORT, or use --emit to dump the proof",
              file=sys.stderr)
        sys.exit(1)

    from pwn import remote
    r = remote(host, int(port))
    print(r.recvline().decode().strip(), file=sys.stderr)
    for p in payloads:
        r.recvuntil(b"send fiat shamir proof: '")
        r.sendline(p.encode())
    # ~1 MB of proof: the server needs a while to open 128 rounds of Pedersen
    # commitments, and stays silent until it starts printing verdicts.
    print(r.recvall(timeout=300).decode())


if __name__ == "__main__":
    main()
