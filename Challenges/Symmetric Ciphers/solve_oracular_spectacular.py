#!/usr/bin/env python3
from pwn import remote, context
import json
import sys
from typing import List

context.log_level = "info"

HOST = "socket.cryptohack.org"
PORT = 13423

# After inverting the oracle output, it is correct 60% of the time:
# P(oracle=True | padding_good)  = 0.6
# P(oracle=True | padding_bad)   = 0.4
P_TRUE_IF_GOOD = 0.6
P_TRUE_IF_BAD  = 0.4

# Confidence threshold per byte hypothesis
THRESH = 0.995

HEX_BYTES = b"0123456789abcdef"

def recv_json_line(io):
    """
    CryptoHack listener often prints banner text before JSON.
    Read lines until we can parse JSON.
    """
    while True:
        line = io.recvline(timeout=5)
        if not line:
            raise EOFError("Connection closed while waiting for JSON")
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line.decode())
        except Exception:
            # banner / non-json
            continue

def json_send(io, obj):
    io.sendline(json.dumps(obj).encode())

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class BayesianChooser:
    """
    Bayesian identification of the correct candidate among N possibilities,
    given a noisy boolean oracle that says True/False with known FP/FN rates.

    Here, each query tests exactly one candidate c:
      - if c is correct: oracle True w/ P_TRUE_IF_GOOD, False otherwise
      - if c is wrong:   oracle True w/ P_TRUE_IF_BAD,  False otherwise
    """
    def __init__(self, candidates: List[int], threshold: float = THRESH):
        self.cands = candidates[:]  # list of byte values
        n = len(self.cands)
        self.p = [1.0 / n] * n
        self.threshold = threshold
        self.total_queries = 0

    def best_index(self) -> int:
        return max(range(len(self.p)), key=lambda i: self.p[i])

    def best_prob(self) -> float:
        return self.p[self.best_index()]

    def update(self, idx: int, oracle_says_good: bool):
        """
        Update posterior after querying candidates[idx] and seeing result.
        """
        self.total_queries += 1

        if oracle_says_good:
            like_correct = P_TRUE_IF_GOOD
            like_wrong   = P_TRUE_IF_BAD
        else:
            like_correct = 1.0 - P_TRUE_IF_GOOD
            like_wrong   = 1.0 - P_TRUE_IF_BAD

        # Multiply all hypotheses by like_wrong (since for all i!=idx they are "wrong" w.r.t queried cand)
        for i in range(len(self.p)):
            self.p[i] *= like_wrong
        # Replace idx factor with like_correct
        self.p[idx] = (self.p[idx] / like_wrong) * like_correct

        # Normalize
        s = sum(self.p)
        if s == 0:
            # Shouldn't happen with sane params, but guard anyway
            n = len(self.p)
            self.p = [1.0 / n] * n
        else:
            self.p = [x / s for x in self.p]

    def run(self, query_func):
        """
        query_func(candidate_byte_value) -> bool (oracle says padding GOOD)
        """
        i = 0
        while self.best_prob() < self.threshold:
            idx = self.best_index()           # greedy: query current best
            cand = self.cands[idx]
            res = query_func(cand)
            if i % 50 == 0:
                print("idx round: ", i)
                print("idx, res: ", idx, ", ", res)
            i += 1
            self.update(idx, res)
        return self.cands[self.best_index()]

def solve_block_with_hex_constraint(io, fixed_iv: bytes, prev_block: bytes, target_block: bytes, prev_is_iv: bool) -> bytes:
    """
    Recover intermediate value I = D_k(C_target) for one block using a noisy padding oracle.

    If prev_is_iv=True: prev_block is the IV (we modify IV), ciphertext is target_block only.
    Else: prev_block is C_{i-1} (we modify that block), and IV stays fixed_iv.

    Because plaintext is hex-ascii, for each byte position we restrict candidates to 16 values:
      c_prev_mod[i] = plaintext_byte ^ prev_block_original[i] ^ pad_len
      where plaintext_byte ∈ b"0123456789abcdef"
    """
    assert len(prev_block) == 16 and len(target_block) == 16
    I = [0] * 16  # intermediate bytes

    def oracle_unpad(ct_hex: str) -> bool:
        """
        Server returns result = good XOR (rng.random() > 0.4), i.e. flipped with prob 0.6.
        Invert it so "True means good" with prob 0.6 (matches NCC-style 0.4 FP/FN).
        """
        json_send(io, {"option": "unpad", "ct": ct_hex})
        resp = recv_json_line(io)
        if "result" not in resp:
            raise RuntimeError(f"Unexpected oracle response: {resp}")
        liar = bool(resp["result"])
        return (not liar)  # invert -> "mostly truthful" oracle

    for pad_len in range(1, 17):
        pos = 16 - pad_len
        print("pad_len: ", pad_len)

        # Build a mutable previous block (IV or C_{i-1}) we will send
        prev_mod = bytearray(prev_block)

        # Set already-solved suffix bytes to enforce padding
        for j in range(15, pos, -1):
            prev_mod[j] = I[j] ^ pad_len

        # Candidate set using the known structure of the ORIGINAL plaintext:
        # I[pos] = P[pos] ^ prev_block[pos], with P[pos] in HEX_BYTES
        # prev_mod[pos] must equal I[pos] ^ pad_len
        candidates = [ (hb ^ prev_block[pos] ^ pad_len) for hb in HEX_BYTES ]

        def query_func(cand_byte: int) -> bool:
            prev_mod[pos] = cand_byte

            if prev_is_iv:
                iv = bytes(prev_mod)
                ct = target_block
            else:
                iv = fixed_iv
                ct = bytes(prev_mod) + target_block

            full = iv + ct
            return oracle_unpad(full.hex())

        chooser = BayesianChooser(candidates, threshold=THRESH)
        chosen = chooser.run(query_func)
        print("Chosen: ", chosen)

        # Recover intermediate byte
        I[pos] = chosen ^ pad_len

    return bytes(I)

def main():
    io = remote(HOST, PORT)

    # Grab ciphertext
    json_send(io, {"option": "encrypt"})
    enc = recv_json_line(io)
    print("enc: ", enc)
    if "ct" not in enc:
        raise RuntimeError(f"Unexpected encrypt response: {enc}")

    full = bytes.fromhex(enc["ct"])
    if len(full) != 16 + 32:
        raise RuntimeError(f"Expected 48 bytes (IV+2 blocks), got {len(full)}")

    IV = full[:16]
    C1 = full[16:32]
    C2 = full[32:48]

    print("iv: ", IV)

    # Decrypt block 2 first (modify C1, keep IV fixed)
    print("Enter P2 solving")
    I2 = solve_block_with_hex_constraint(io, fixed_iv=IV, prev_block=C1, target_block=C2, prev_is_iv=False)
    P2 = xor_bytes(I2, C1)
    print("P2: ", P2)

    print("Enter P1 solving")
    # Decrypt block 1 by truncating to (IV, C1) and modifying IV
    I1 = solve_block_with_hex_constraint(io, fixed_iv=b"", prev_block=IV, target_block=C1, prev_is_iv=True)
    P1 = xor_bytes(I1, IV)
    print("P1: ", P1)

    msg_bytes = P1 + P2

    # Should be ASCII hex
    try:
        msg = msg_bytes.decode("ascii")
    except Exception:
        raise RuntimeError(f"Recovered non-ascii message: {msg_bytes!r}")

    # Sanity: must be 32 chars of hex
    if len(msg) != 32 or any(c not in "0123456789abcdef" for c in msg):
        raise RuntimeError(f"Recovered message doesn't look like hex: {msg!r}")

    # Submit to get flag
    json_send(io, {"option": "check", "message": msg})
    resp = recv_json_line(io)
    print(resp)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)