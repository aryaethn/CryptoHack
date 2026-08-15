import json

from pwn import remote

from hamiltonicity_lib import (
    commit_to_graph,
    comm_params,
    get_r_vals,
    hash_committed_graph,
)

HOST = "archive.cryptohack.org"
PORT = 14635

N = 5
NUMROUNDS = 128

# A dummy graph that actually *does* have a Hamiltonian cycle -- the complete
# graph on N nodes. The real secret graph G has none, but testcycle() only
# ever checks self-consistency of the committed matrix A we send; it never
# compares A back against the real G (that comparison only happens on the
# challenge==0 branch). So instead of committing to a permutation of the real
# G, we commit to this dummy graph and open its trivial cycle 0->1->...->4->0
# whenever the Fiat-Shamir challenge bit comes out as 1.
#
# Since we (the prover) pick the commitment randomness before the challenge
# is derived from it, and the "verifier" challenge is just one bit of
# SHA256(state || A), we can grind: re-commit with fresh randomness until the
# derived bit is 1, then always answer on the branch we can satisfy.
G_dummy = [[1 if i != j else 0 for j in range(N)] for i in range(N)]
cycle = [[i, (i + 1) % N] for i in range(N)]

r = remote(HOST, PORT)
print(r.recvline().decode())

FS_state = b""
for rnd in range(NUMROUNDS):
    r.recvuntil(b"send fiat shamir proof: '")

    while True:
        A, openings = commit_to_graph(G_dummy, N)
        candidate_state = hash_committed_graph(A, FS_state, comm_params)
        if candidate_state[-1] & 1 == 1:
            break

    FS_state = candidate_state
    rvals = get_r_vals(openings, N, cycle)
    payload = {"A": A, "z": [cycle, rvals]}
    r.sendline(json.dumps(payload).encode())

    resp = r.recvline().decode().strip()
    if resp != "accepted":
        print(f"round {rnd}: unexpected response: {resp!r}")
        break
    if rnd % 16 == 0:
        print(f"round {rnd}: {resp}")

print(r.recvall(timeout=5).decode())
