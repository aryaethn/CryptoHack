from pwn import remote
import json, math, sys
from collections import defaultdict

HOST, PORT = 'socket.cryptohack.org', 13423

HEX_BYTES = b'0123456789abcdef'  # plaintext is ASCII hex

# --- likelihoods for the lying oracle ---
# Oracle: result = good ^ (U > 0.4). So:
#   correct guess (good=True)  -> True ~ 0.4
#   wrong   guess (good=False) -> True ~ 0.6
P_CORRECT_TRUE = 0.4
P_WRONG_TRUE   = 0.6
LOG15 = math.log(P_WRONG_TRUE / P_CORRECT_TRUE)  # log(1.5)

# tuning defaults
DEFAULT_INIT = 4
DEFAULT_GROWTH = 2
DEFAULT_GAP = math.log(30.0)     # ~97% odds vs runner-up
DEFAULT_PER_BYTE_CAP = 260
DEFAULT_GLOBAL_CAP = 11800

def llr_gap(best_llr, second_llr):
    return best_llr - second_llr

def llr(true_cnt, total):
    # LLR(correct vs wrong) up to constant:
    # log [ 0.4^(T) * 0.6^(F) / (0.6^(T) * 0.4^(F)) ]  (with True-count=T)
    # Simplifies to: (n - 2*T) * log(1.5)
    return (total - 2*true_cnt) * LOG15

class Oracle:
    def __init__(self, host, port):
        self.r = remote(host, port)
        banner = self.r.recvline().decode().strip()
        print(banner)
        print("Oracle ready")

    def encrypt(self):
        self.r.sendline(json.dumps({"option": "encrypt"}).encode())
        res = json.loads(self.r.recvline().decode())
        ct = bytes.fromhex(res["ct"])
        return ct[:16], ct[16:]  # (IV, CT)

    def unpad(self, forged):
        self.r.sendline(json.dumps({"option":"unpad","ct":forged.hex()}).encode())
        res = json.loads(self.r.recvline().decode())
        return bool(res["result"])

    def check(self, msg_ascii):
        self.r.sendline(json.dumps({"option":"check","message":msg_ascii}).encode())
        return self.r.recvline().decode().strip()

def forge_prev(previous, known_plain, i, cand_byte, pad):
    fp = bytearray(previous)
    # suffix bytes j>i must decrypt to pad
    for j in range(i+1, 16):
        fp[j] = previous[j] ^ known_plain[j] ^ pad
    # current byte i: makes P'[i] = P[i] ^ cand ^ pad
    # so P'[i] == pad  iff cand == P[i]
    fp[i] = previous[i] ^ cand_byte ^ pad
    return bytes(fp)

def sample_arm(oracle, prev, ctb, known_plain, i, cand, pad, k):
    t = 0
    for _ in range(k):
        fprev = forge_prev(prev, known_plain, i, cand, pad)
        res = oracle.unpad(fprev + ctb)
        t += 1 if res else 0
    return t, k

def successive_halving_byte(oracle, prev, ctb, known_plain, i,
                            init_per_arm=DEFAULT_INIT, growth=DEFAULT_GROWTH, gap_log_odds=DEFAULT_GAP,
                            per_byte_cap=DEFAULT_PER_BYTE_CAP, global_left=None):
    """
    Find plaintext[i] using successive halving + LLR and a hard per-byte cap.
    Returns (winner_byte, spent_queries, final_gap).
    """
    pad = 16 - i
    arms = list(HEX_BYTES)
    true_counts = defaultdict(int)
    totals = defaultdict(int)
    spent = 0
    per_round = init_per_arm

    def can_spend(more):
        if spent + more > per_byte_cap:
            return False
        if global_left is not None and spent + more > global_left:
            return False
        return True

    need = len(arms) * per_round
    if not can_spend(need):
        per_round = max(1, (per_byte_cap - spent) // max(1, len(arms)))
    for a in arms:
        t, n = sample_arm(oracle, prev, ctb, known_plain, i, a, pad, per_round)
        true_counts[a] += t
        totals[a] += n
    spent += len(arms) * per_round

    while len(arms) > 1:
        scored = sorted(arms, key=lambda a: llr(true_counts[a], totals[a]), reverse=True)
        best, second = scored[0], scored[1]
        gap_now = llr_gap(llr(true_counts[best], totals[best]), llr(true_counts[second], totals[second]))
        if gap_now >= gap_log_odds:
            return best, spent, gap_now

        keep = (len(arms) + 1) // 2
        arms = scored[:keep]

        per_round *= growth
        need = len(arms) * per_round
        if not can_spend(need):
            possible = max(0, min(per_byte_cap - spent, (global_left - spent) if global_left else per_byte_cap - spent))
            per_arm_extra = possible // max(1, len(arms))
            if per_arm_extra > 0:
                for a in arms:
                    t, n = sample_arm(oracle, prev, ctb, known_plain, i, a, pad, per_arm_extra)
                    true_counts[a] += t
                    totals[a] += n
                spent += per_arm_extra * len(arms)
            # finalize with current best
            scored = sorted(arms, key=lambda a: llr(true_counts[a], totals[a]), reverse=True)
            best, second = scored[0], (scored[1] if len(scored) > 1 else best)
            gap_now = llr_gap(llr(true_counts[best], totals[best]), llr(true_counts[second], totals[second]))
            return best, spent, gap_now

        for a in arms:
            t, n = sample_arm(oracle, prev, ctb, known_plain, i, a, pad, per_round)
            true_counts[a] += t
            totals[a] += n
        spent += len(arms) * per_round

    # only one arm remains
    only = arms[0]
    return only, spent, float("inf")

def refine_byte(oracle, prev, ctb, known_plain, i,
                extra_cap, target_gap=math.log(200.0), init=3, batch=8):
    """
    Lightweight re-check for a single position i:
      1) small sweep to rank top-2 candidates,
      2) sample top-2 in matched batches until gap >= target or extra_cap used.
    Returns (winner_byte, extra_spent, final_gap).
    """
    pad = 16 - i
    # small sweep
    true_counts = {a: 0 for a in HEX_BYTES}
    totals = {a: 0 for a in HEX_BYTES}
    spent = 0
    for a in HEX_BYTES:
        t, n = sample_arm(oracle, prev, ctb, known_plain, i, a, pad, init)
        true_counts[a] += t
        totals[a] += n
    spent += init * len(HEX_BYTES)

    ranked = sorted(HEX_BYTES, key=lambda a: llr(true_counts[a], totals[a]), reverse=True)
    best, second = ranked[0], ranked[1]
    def cur_gap():
        return llr(true_counts[best], totals[best]) - llr(true_counts[second], totals[second])

    while spent + 2*batch <= extra_cap and cur_gap() < target_gap:
        t1, n1 = sample_arm(oracle, prev, ctb, known_plain, i, best, pad, batch)
        t2, n2 = sample_arm(oracle, prev, ctb, known_plain, i, second, pad, batch)
        true_counts[best] += t1; totals[best] += n1
        true_counts[second] += t2; totals[second] += n2
        spent += 2*batch
        # keep top-2 updated
        ranked = sorted([best, second], key=lambda a: llr(true_counts[a], totals[a]), reverse=True)
        best, second = ranked[0], ranked[1]

    gap_final = cur_gap()
    return best, spent, gap_final

def refine_block(oracle, previous, ctb, plain, gaps, global_budget_left,
                 k=6, per_byte_extra_cap=200, target_gap=math.log(300.0)):
    """
    Focus extra budget on the K weakest positions (smallest gaps), in descending i order.
    Mutates `plain` in-place if a better candidate is found.
    Returns total extra queries spent.
    """
    idxs = sorted(range(16), key=lambda x: gaps[x])[:k]
    idxs.sort(reverse=True)  # descending to ensure suffix correctness
    spent = 0
    for i in idxs:
        # guard remaining global budget
        if global_budget_left is not None and spent + per_byte_extra_cap > global_budget_left:
            break
        winner, extra, gap_final = refine_byte(
            oracle, previous, ctb, plain, i,
            extra_cap=per_byte_extra_cap, target_gap=target_gap
        )
        spent += extra
        if winner != plain[i]:
            old = chr(plain[i]); new = chr(winner)
            plain[i] = winner
            print(f"[refine i={i:02d}] {old} -> {new}  (extra {extra}, gap {gap_final:.2f})")
        else:
            print(f"[refine i={i:02d}] kept {chr(winner)}  (extra {extra}, gap {gap_final:.2f})")
    return spent

def attack_block(oracle, previous, ctb,
                 init_per_arm=DEFAULT_INIT, growth=DEFAULT_GROWTH, gap_log_odds=DEFAULT_GAP,
                 per_byte_cap=DEFAULT_PER_BYTE_CAP, global_budget_left=None):
    plain = bytearray(16)
    used = 0
    gaps = [0.0]*16
    for i in range(15, -1, -1):
        bytes_left = i + 1
        if global_budget_left is not None:
            reserve_each = 140
            max_for_this = max(120, global_budget_left - used - (bytes_left - 1) * reserve_each)
            cap = min(per_byte_cap, max_for_this)
        else:
            cap = per_byte_cap

        cand, spent, gap = successive_halving_byte(
            oracle, previous, ctb, plain, i,
            init_per_arm=init_per_arm, growth=growth,
            gap_log_odds=gap_log_odds, per_byte_cap=cap,
            global_left=(global_budget_left - used) if global_budget_left else None
        )
        plain[i] = cand
        gaps[i] = gap
        used += spent
        print(f"[i={i:02d}] chose {chr(cand)}  (byte spent {spent}, gap {gap:.2f}, total {used})")
    return bytes(plain), used, gaps

def main():
    o = Oracle(HOST, PORT)

    iv, ct = o.encrypt()
    c1, c2 = ct[:16], ct[16:] if len(ct) == 32 else (ct, b"")
    print(f"IV  = {iv.hex()}")
    print(f"C1  = {c1.hex()}")
    if c2:
        print(f"C2  = {c2.hex()}")

    spent = 0
    print("\n[+] Attacking first block...")
    p1, q1, g1 = attack_block(
        o, iv, c1,
        init_per_arm=DEFAULT_INIT, growth=DEFAULT_GROWTH, gap_log_odds=DEFAULT_GAP,
        per_byte_cap=DEFAULT_PER_BYTE_CAP, global_budget_left=DEFAULT_GLOBAL_CAP
    )
    spent += q1
    print(f"Recovered P1: {p1!r}  (spent {spent})")

    # Refinement pass on block 1
    extra1 = refine_block(
        o, iv, c1, bytearray(p1), g1,
        global_budget_left=(DEFAULT_GLOBAL_CAP - spent),
        k=6, per_byte_extra_cap=200, target_gap=math.log(300.0)
    )
    spent += extra1
    p1 = bytes(bytearray(p1))  # ensure bytes

    if c2:
        print("\n[+] Attacking second block...")
        p2, q2, g2 = attack_block(
            o, c1, c2,
            init_per_arm=DEFAULT_INIT, growth=DEFAULT_GROWTH, gap_log_odds=DEFAULT_GAP,
            per_byte_cap=DEFAULT_PER_BYTE_CAP, global_budget_left=(DEFAULT_GLOBAL_CAP - spent)
        )
        spent += q2
        print(f"Recovered P2: {p2!r}  (spent {spent})")

        # Refinement pass on block 2
        extra2 = refine_block(
            o, c1, c2, bytearray(p2), g2,
            global_budget_left=(DEFAULT_GLOBAL_CAP - spent),
            k=6, per_byte_extra_cap=200, target_gap=math.log(300.0)
        )
        spent += extra2
        p2 = bytes(bytearray(p2))
        full = p1 + p2
    else:
        full = p1

    try:
        msg = full.decode('ascii')
        print(f"\n[+] Message: {msg}")
        print(o.check(msg))
    except UnicodeDecodeError:
        print("\n[!] Decoding failed — increase target gaps or caps and retry.")

if __name__ == "__main__":
    main()