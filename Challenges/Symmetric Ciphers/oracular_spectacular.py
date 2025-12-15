#!/usr/bin/env python3
import socket
import json
import math
import random
import itertools
from typing import List, Tuple

# =========================
# Connection / IO
# =========================

HOST = "socket.cryptohack.org"
PORT = 13423
LOG_FILE = "oracular_spectacular_log.txt"

# =========================
# Challenge structure
# =========================

TOTAL_BYTES = 32            # the message length in bytes
NIBBLES = 16                # candidates: '0'..'f'
HEX_CHARS = "0123456789abcdef"

# Oracle bias model (from hint)
P_TRUE_CORRECT = 0.4        # P(True | correct nibble)
P_TRUE_WRONG = 0.6          # P(True | wrong nibble)

# Global query cap (leave a margin under 12000)
MAX_UNPAD_QUERIES = 11900

# =========================
# Stage 1 parameters
# =========================

INIT_QUERIES = 7              # initial uniform sampling per nibble
STAGE1_MAX_PER_BYTE = 200     # soft cap per byte
DELTA_LLR_STAGE1 = 3.0        # evidence gap target in Stage 1

# =========================
# Stage 2 parameters
# =========================

DELTA_LLR_STAGE2 = 2.5        # evidence gap target in Stage 2
STAGE2_RANDOM_OTHER_PROB = 0.15
STAGE2_REFRESH_EVERY = 180    # every this many Stage2 steps, do a full 16-nibble refresh
STAGE2_MAX_STEPS = 200000     # safety guard

# =========================
# Endgame search parameters
# =========================

ENDGAME_WORST_BYTES = 6       # choose worst W bytes by LLR gap
ENDGAME_TOP_K = 2             # keep top K candidates for each of those bytes
ENDGAME_MAX_COMBOS = 5000     # safety guard (2^6=64 normally)

# Random seed for reproducibility if you want
# random.seed(1337)


# =========================
# Logging
# =========================

def reset_log():
    with open(LOG_FILE, "w") as f:
        f.write("Oracular Spectacular solver log (LLR softmax + refresh refinement + endgame)\n")

def log(msg: str):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")


# =========================
# Network helpers
# =========================

def recvline(sock: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed the connection unexpectedly")
        data += chunk
    return data.decode().rstrip("\r\n")

def send_cmd(sock: socket.socket, msg: dict) -> dict:
    sock.sendall(json.dumps(msg).encode() + b"\n")
    line = recvline(sock)
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        log(f"[!] JSON decode error: {line!r}")
        raise

def get_ciphertext(sock: socket.socket) -> str:
    resp = send_cmd(sock, {"option": "encrypt"})
    if "ct" not in resp:
        raise ValueError(f"No 'ct' in response: {resp}")
    return resp["ct"]

def check_padding(sock: socket.socket, ct_hex: str) -> bool:
    resp = send_cmd(sock, {"option": "unpad", "ct": ct_hex})
    if "result" not in resp:
        raise ValueError(f"No 'result' in response: {resp}")
    return bool(resp["result"])

def check_message(sock: socket.socket, message: str) -> dict:
    return send_cmd(sock, {"option": "check", "message": message})


# =========================
# CBC padding-oracle crafting
# =========================

def join_to_hex(arr: List[int]) -> str:
    return "".join(f"{b:02x}" for b in arr)

def build_ct_hex(known_len: int, decrypted_arr: List[int], candidate_char: str,
                 iv_arr: List[int], ct1_arr: List[int], ct2_arr: List[int]) -> str:
    """
    Build ciphertext hex for padding oracle on a 2-block CBC construction.

    - known_len: number of bytes already fixed from the end (0..31)
    - decrypted_arr: foundX values for those bytes in order [last, last-1, ...]
    - candidate_char: plaintext guess at current byte (ASCII hex char)
    """
    attacking_index = known_len
    is_first_block = known_len < 16
    padding_size = (known_len % 16) + 1
    target_value = padding_size

    replacing_values = [decrypted_arr[idx] ^ target_value for idx in range(known_len)]

    replaced_iv_arr = iv_arr.copy()
    replaced_ct1_arr = ct1_arr.copy()

    for idx in range(known_len):
        if idx < 16:
            if is_first_block:
                replaced_ct1_arr[len(replaced_ct1_arr) - idx - 1] = replacing_values[idx]
        else:
            replaced_iv_arr[len(replaced_iv_arr) - (idx - 16) - 1] = replacing_values[idx]

    if is_first_block:
        base_byte = ct1_arr[len(ct1_arr) - known_len - 1]
    else:
        base_byte = iv_arr[len(iv_arr) - (known_len - 16) - 1]

    candidate_ord = ord(candidate_char)
    found_x = candidate_ord ^ base_byte
    attacking_value = found_x ^ target_value

    if is_first_block:
        replace_index = len(replaced_ct1_arr) - attacking_index - 1
        replaced_ct1_arr[replace_index] = attacking_value
        combined = replaced_iv_arr + replaced_ct1_arr + ct2_arr
    else:
        replace_index = len(replaced_iv_arr) - (attacking_index - 16) - 1
        replaced_iv_arr[replace_index] = attacking_value
        combined = replaced_iv_arr + replaced_ct1_arr

    return join_to_hex(combined)

def compute_found_x_for_candidate(known_len: int, candidate_char: str,
                                  iv_arr: List[int], ct1_arr: List[int]) -> int:
    is_first_block = known_len < 16
    if is_first_block:
        base_byte = ct1_arr[len(ct1_arr) - known_len - 1]
    else:
        base_byte = iv_arr[len(iv_arr) - (known_len - 16) - 1]
    return ord(candidate_char) ^ base_byte


# =========================
# LLR + stable posterior
# =========================

def llr_win_vs_lose(e_true: int, n_total: int) -> float:
    """
    LLR = log P(data | win) - log P(data | lose)
        = E log(0.4/0.6) + (N-E) log(0.6/0.4)
    """
    if n_total == 0:
        return 0.0
    return (
        e_true * math.log(P_TRUE_CORRECT / P_TRUE_WRONG) +
        (n_total - e_true) * math.log((1 - P_TRUE_CORRECT) / (1 - P_TRUE_WRONG))
    )

def llrs_for_byte(E: List[int], N: List[int]) -> List[float]:
    return [llr_win_vs_lose(E[i], N[i]) for i in range(NIBBLES)]

def softmax_from_llrs(llrs: List[float]) -> List[float]:
    """
    Posterior over 16 hypotheses is proportional to exp(LLR_i) under uniform prior,
    because logL(hypothesis i) = constant + LLR_i.
    This is the stable, correct, and fast way to compute posteriors here.
    """
    m = max(llrs)
    exps = [math.exp(x - m) for x in llrs]
    s = sum(exps)
    if s == 0.0:
        # Extremely unlikely with stabilization, but guard anyway.
        return [1.0 / NIBBLES] * NIBBLES
    return [v / s for v in exps]

def topk_indices_by_llr(llrs: List[float], k: int = 2) -> List[int]:
    return sorted(range(NIBBLES), key=lambda i: llrs[i], reverse=True)[:k]

def llr_gap_for_byte(E: List[int], N: List[int]) -> Tuple[float, int, int, List[float], List[float]]:
    llrs = llrs_for_byte(E, N)
    order = sorted(range(NIBBLES), key=lambda i: llrs[i], reverse=True)
    best, second = order[0], order[1]
    gap = llrs[best] - llrs[second]
    post = softmax_from_llrs(llrs)
    return gap, best, second, llrs, post


# =========================
# Stage 2 query helper
# =========================

def query_candidate_global(sock: socket.socket, byte_index: int, candidate_char: str,
                           found_x_full: List[int],
                           iv_arr: List[int], ct1_arr: List[int], ct2_arr: List[int]) -> bool:
    known_len = TOTAL_BYTES - 1 - byte_index

    decrypted_arr = []
    for idx in range(TOTAL_BYTES - 1, byte_index, -1):
        fx = found_x_full[idx]
        if fx is None:
            raise RuntimeError(f"Missing foundX for byte {idx} while refining byte {byte_index}")
        decrypted_arr.append(fx)

    ct_guess = build_ct_hex(known_len, decrypted_arr, candidate_char, iv_arr, ct1_arr, ct2_arr)
    return check_padding(sock, ct_guess)


# =========================
# Main solver
# =========================

def solve():
    reset_log()
    log("[+] Connecting to server...")

    with socket.create_connection((HOST, PORT)) as sock:
        banner = recvline(sock)
        log(f"[+] Banner: {banner}")

        ct_hex = get_ciphertext(sock)
        log(f"[+] Ciphertext: {ct_hex}")

        ct_bytes = bytes.fromhex(ct_hex)
        if len(ct_bytes) != 48:
            log(f"[!] Unexpected ciphertext length: {len(ct_bytes)} bytes (expected 48)")

        iv_arr = list(ct_bytes[:16])
        ct1_arr = list(ct_bytes[16:32])
        ct2_arr = list(ct_bytes[32:48])

        # Counts per byte/nibble
        E_global = [[0] * NIBBLES for _ in range(TOTAL_BYTES)]
        N_global = [[0] * NIBBLES for _ in range(TOTAL_BYTES)]

        # Track historical max LLR per nibble (for robust fallback)
        max_llr_global = [[-1e9] * NIBBLES for _ in range(TOTAL_BYTES)]

        found_x_full = [None] * TOTAL_BYTES
        message_chars = ["?"] * TOTAL_BYTES

        global_unpad_queries = 0
        ambiguous = set()

        # -------------------------
        # Stage 1: sequential recovery from end
        # -------------------------
        decrypted_arr = []  # foundX suffix in order [last, last-1, ...]

        for known_len in range(TOTAL_BYTES):
            byte_index = TOTAL_BYTES - 1 - known_len
            log(f"\n[+] ==== Stage 1: byte {byte_index} (known_len={known_len}) ====")

            E = E_global[byte_index]
            N = N_global[byte_index]
            byte_q = 0

            # Init uniform sampling
            log(f"[+] Stage1 init: {INIT_QUERIES} queries per nibble")
            for _ in range(INIT_QUERIES):
                for ci, c in enumerate(HEX_CHARS):
                    if global_unpad_queries >= MAX_UNPAD_QUERIES:
                        break
                    ct_guess = build_ct_hex(known_len, decrypted_arr, c, iv_arr, ct1_arr, ct2_arr)
                    res = check_padding(sock, ct_guess)

                    global_unpad_queries += 1
                    byte_q += 1

                    if res:
                        E[ci] += 1
                    N[ci] += 1

                    llr_val = llr_win_vs_lose(E[ci], N[ci])
                    if llr_val > max_llr_global[byte_index][ci]:
                        max_llr_global[byte_index][ci] = llr_val

                if global_unpad_queries >= MAX_UNPAD_QUERIES:
                    break

            # Adaptive sampling on best LLR
            while byte_q < STAGE1_MAX_PER_BYTE and global_unpad_queries < MAX_UNPAD_QUERIES:
                gap, best, second, llrs, post = llr_gap_for_byte(E, N)

                log(
                    f"[+] Stage1 byte {byte_index}: "
                    f"best='{HEX_CHARS[best]}' LLR={llrs[best]:.4f} post={post[best]:.4f} | "
                    f"second='{HEX_CHARS[second]}' LLR={llrs[second]:.4f} post={post[second]:.4f} | "
                    f"gap={gap:.4f} | byte_q={byte_q}"
                )

                if gap >= DELTA_LLR_STAGE1:
                    log(f"[+] Stage1 byte {byte_index}: gap ≥ {DELTA_LLR_STAGE1} reached.")
                    break

                # Query current best
                c = HEX_CHARS[best]
                ct_guess = build_ct_hex(known_len, decrypted_arr, c, iv_arr, ct1_arr, ct2_arr)
                res = check_padding(sock, ct_guess)

                global_unpad_queries += 1
                byte_q += 1

                if res:
                    E[best] += 1
                N[best] += 1

                llr_val = llr_win_vs_lose(E[best], N[best])
                if llr_val > max_llr_global[byte_index][best]:
                    max_llr_global[byte_index][best] = llr_val

            # Choose best LLR to continue CBC
            gap, best, second, llrs, post = llr_gap_for_byte(E, N)
            chosen_idx = best
            chosen_char = HEX_CHARS[chosen_idx]

            if gap < DELTA_LLR_STAGE1:
                ambiguous.add(byte_index)
                log(
                    f"[!] Stage1 byte {byte_index}: ambiguous after cap "
                    f"(gap={gap:.4f} < {DELTA_LLR_STAGE1}). "
                    f"Proceeding with best '{chosen_char}'."
                )
            else:
                log(f"[+] Stage1 byte {byte_index}: confident. Chosen '{chosen_char}'.")

            found_x = compute_found_x_for_candidate(known_len, chosen_char, iv_arr, ct1_arr)
            decrypted_arr.append(found_x)
            found_x_full[byte_index] = found_x
            message_chars[byte_index] = chosen_char

            log(f"[+] Stage1 partial message: {''.join(message_chars)}")
            log(f"[+] Global unpad queries: {global_unpad_queries}")

            if global_unpad_queries >= MAX_UNPAD_QUERIES:
                log("[!] Global cap reached in Stage 1.")
                break

        # -------------------------
        # Stage 2: global uncertainty refinement
        # -------------------------
        remaining = MAX_UNPAD_QUERIES - global_unpad_queries
        log(f"\n[+] Stage1 done. Ambiguous bytes: {sorted(ambiguous)}")
        log(f"[+] Remaining unpad queries for Stage2: {remaining}")

        step = 0
        while remaining > 0 and ambiguous and step < STAGE2_MAX_STEPS:
            step += 1

            # Filter to still-ambiguous by current gap
            amb_list = []
            for b in ambiguous:
                gap, best, second, llrs, post = llr_gap_for_byte(E_global[b], N_global[b])
                if gap < DELTA_LLR_STAGE2:
                    amb_list.append((gap, b, best, second, llrs, post))

            if not amb_list:
                log("[+] Stage2: all ambiguous bytes now meet gap target.")
                break

            # Pick byte with smallest gap (most uncertain)
            amb_list.sort(key=lambda x: x[0])
            gap, byte_index, best, second, llrs, post = amb_list[0]
            E = E_global[byte_index]
            N = N_global[byte_index]

            # Periodic full refresh of all 16 nibbles for this worst byte
            if step % STAGE2_REFRESH_EVERY == 0:
                log(f"[+] Stage2 step {step}: REFRESH byte {byte_index} (gap={gap:.4f})")
                for ci, c in enumerate(HEX_CHARS):
                    if remaining <= 0 or global_unpad_queries >= MAX_UNPAD_QUERIES:
                        break
                    res = query_candidate_global(sock, byte_index, c, found_x_full, iv_arr, ct1_arr, ct2_arr)
                    global_unpad_queries += 1
                    remaining -= 1

                    if res:
                        E[ci] += 1
                    N[ci] += 1

                    llr_val = llr_win_vs_lose(E[ci], N[ci])
                    if llr_val > max_llr_global[byte_index][ci]:
                        max_llr_global[byte_index][ci] = llr_val

                continue

            # Otherwise: sharpen best vs second, with small chance of random other
            r = random.random()
            if r < STAGE2_RANDOM_OTHER_PROB:
                candidates = [i for i in range(NIBBLES) if i not in (best, second)]
                chosen_idx = random.choice(candidates) if candidates else best
                label = "random_other"
            else:
                chosen_idx = best if (step % 2 == 1) else second
                label = "best" if chosen_idx == best else "second"

            chosen_char = HEX_CHARS[chosen_idx]

            log(
                f"[+] Stage2 step {step}: byte {byte_index} gap={gap:.4f} "
                f"| query {label} '{chosen_char}' "
                f"(best='{HEX_CHARS[best]}' LLR={llrs[best]:.4f} post={post[best]:.4f}, "
                f"second='{HEX_CHARS[second]}' LLR={llrs[second]:.4f} post={post[second]:.4f}) "
                f"| remaining={remaining}"
            )

            res = query_candidate_global(sock, byte_index, chosen_char, found_x_full, iv_arr, ct1_arr, ct2_arr)
            global_unpad_queries += 1
            remaining -= 1

            if res:
                E[chosen_idx] += 1
            N[chosen_idx] += 1

            llr_val = llr_win_vs_lose(E[chosen_idx], N[chosen_idx])
            if llr_val > max_llr_global[byte_index][chosen_idx]:
                max_llr_global[byte_index][chosen_idx] = llr_val

            # Occasionally re-evaluate ambiguous set
            if step % 200 == 0:
                new_amb = set()
                for b in ambiguous:
                    g, _, _, _, _ = llr_gap_for_byte(E_global[b], N_global[b])
                    if g < DELTA_LLR_STAGE2:
                        new_amb.add(b)
                ambiguous = new_amb
                log(f"[+] Stage2 progress: step={step}, remaining ambiguous={sorted(ambiguous)}")

        # Final ambiguous refresh
        new_amb = set()
        for b in ambiguous:
            g, _, _, _, _ = llr_gap_for_byte(E_global[b], N_global[b])
            if g < DELTA_LLR_STAGE2:
                new_amb.add(b)
        ambiguous = new_amb

        log(f"\n[+] Stage2 complete. Remaining ambiguous bytes: {sorted(ambiguous)}")
        log(f"[+] Total unpad queries used: {global_unpad_queries}")

        # -------------------------
        # Build MAP message (with historical LLR fallback for ambiguous bytes)
        # -------------------------
        final_chars = ["?"] * TOTAL_BYTES

        gaps_all = []
        top_candidates_per_byte = []

        for byte_index in range(TOTAL_BYTES):
            E = E_global[byte_index]
            N = N_global[byte_index]
            gap, best, second, llrs, post = llr_gap_for_byte(E, N)

            gaps_all.append((gap, byte_index))
            order = sorted(range(NIBBLES), key=lambda i: llrs[i], reverse=True)
            top_candidates_per_byte.append(order)

            if byte_index in ambiguous:
                # choose highest historical max LLR nibble
                hist_idx = max(range(NIBBLES), key=lambda i: max_llr_global[byte_index][i])
                chosen_idx = hist_idx
                reason = "historical_max_llr"
            else:
                chosen_idx = best
                reason = "current_best_llr"

            final_chars[byte_index] = HEX_CHARS[chosen_idx]

            log(
                f"[+] Final byte {byte_index}: '{HEX_CHARS[chosen_idx]}' "
                f"(reason={reason}, gap={gap:.4f}, "
                f"best='{HEX_CHARS[best]}' post={post[best]:.4f}, "
                f"second='{HEX_CHARS[second]}' post={post[second]:.4f})"
            )

        recovered_message = "".join(final_chars)
        log(f"\n[+] MAP candidate message: {recovered_message}")

        # -------------------------
        # Endgame: small combinational search using check()
        # -------------------------
        # Idea: if only a few bytes are wrong, this closes the gap.
        gaps_all.sort(key=lambda x: x[0])  # smallest gap = most uncertain
        worst_bytes = [b for _, b in gaps_all[:ENDGAME_WORST_BYTES]]

        # Build top-K candidate lists for those bytes
        candidate_lists = []
        for b in worst_bytes:
            order = top_candidates_per_byte[b][:ENDGAME_TOP_K]
            candidate_lists.append(order)

        combos = 1
        for lst in candidate_lists:
            combos *= len(lst)

        log(
            f"[+] Endgame: worst bytes by gap: {worst_bytes}, "
            f"topK={ENDGAME_TOP_K}, combos={combos}"
        )

        tried = 0
        found_flag = None

        # Base message indices
        base_indices = []
        for i in range(TOTAL_BYTES):
            # start from current best LLR index
            E = E_global[i]; N = N_global[i]
            _, best, _, llrs, _ = llr_gap_for_byte(E, N)
            base_indices.append(best)

        # Iterate combos
        if combos <= ENDGAME_MAX_COMBOS and combos > 0:
            for choice_tuple in itertools.product(*candidate_lists):
                # build candidate indices
                cand_indices = base_indices[:]
                for w_i, byte_index in enumerate(worst_bytes):
                    cand_indices[byte_index] = choice_tuple[w_i]

                cand_msg = "".join(HEX_CHARS[idx] for idx in cand_indices)

                tried += 1
                resp = check_message(sock, cand_msg)
                if "flag" in resp:
                    found_flag = resp["flag"]
                    log(f"[+] Endgame success after {tried} combos!")
                    log(f"[+] Message: {cand_msg}")
                    log(f"[+] FLAG: {found_flag}")
                    break

                if tried % 50 == 0:
                    log(f"[+] Endgame tried {tried}/{combos} combos...")

        else:
            log("[!] Endgame skipped: too many combos for safety guard.")

        # If endgame failed, still do a final check on MAP message
        if not found_flag:
            resp = check_message(sock, recovered_message)
            log(f"[+] Final check(MAP) response: {resp}")
            if "flag" in resp:
                log(f"[+] FLAG: {resp['flag']}")
            else:
                log("[!] No flag returned. Likely a few stubborn bytes remain.")


solve()