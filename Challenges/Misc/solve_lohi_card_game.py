import json
import re

from pwn import remote

HOST = "socket.cryptohack.org"
PORT = 13383

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']
MOD = 2**61 - 1

HINT_RE = re.compile(r"reshuffle the deck after (\d+) rounds")


def card_to_index(s):
    value, suit = s.split(" of ")
    return SUITS.index(suit) * 13 + VALUES.index(value)


def rebase(n, b=52):
    if n < b:
        return [n]
    return [n % b] + rebase(n // b, b)


class ReplicaGame:
    """Mirrors Game's shuffle/deal_card logic once mul/inc/state are known."""

    def __init__(self, mul, inc, state):
        self.mul = mul
        self.inc = inc
        self.state = state
        self.deals = []

    def next_state(self):
        self.state = (self.state * self.mul + self.inc) % MOD
        return self.state

    def shuffle(self):
        self.deals = rebase(self.next_state())

    def deal_index(self):
        if not self.deals:
            self.shuffle()
        return self.deals.pop()


def digits_to_n(chunk):
    L = len(chunk)
    n = 0
    for j, d in enumerate(chunk):
        n += d * pow(52, L - 1 - j)
    return n


r = remote(HOST, PORT)

seq = []            # deck index dealt at each position (1-indexed via len(seq))
cycle_lengths = []  # lengths of shuffle cycles, in the order encountered

cracked = False
replica = None
predicted = {}       # position (1-indexed) -> predicted deck index, filled in once cracked
next_unpredicted_pos = None

for round_no in range(1, 201):
    resp = json.loads(r.recvline())
    hand_idx = card_to_index(resp["hand"])
    seq.append(hand_idx)

    m = HINT_RE.search(resp.get("msg") or "")
    if m:
        cycle_lengths.append(int(m.group(1)))

    if not cracked and len(cycle_lengths) >= 3 and sum(cycle_lengths[:3]) <= len(seq):
        L1, L2, L3 = cycle_lengths[:3]
        n1 = digits_to_n(seq[0:L1])
        n2 = digits_to_n(seq[L1:L1 + L2])
        n3 = digits_to_n(seq[L1 + L2:L1 + L2 + L3])

        mul = ((n3 - n2) * pow(n2 - n1, -1, MOD)) % MOD
        inc = (n2 - n1 * mul) % MOD

        replica = ReplicaGame(mul, inc, n3)
        next_unpredicted_pos = L1 + L2 + L3 + 1  # positions 1..this-1 already observed directly
        cracked = True
        print(f"[+] Cracked RNG at round {round_no}: mul={mul} inc={inc}")

    next_pos = len(seq) + 1  # position of the card that will be dealt next round
    if cracked:
        while next_unpredicted_pos <= next_pos:
            predicted[next_unpredicted_pos] = replica.deal_index()
            next_unpredicted_pos += 1

        predicted_idx = predicted[next_pos]
        hand_value = hand_idx % 13
        predicted_value = predicted_idx % 13
        choice = "l" if predicted_value < hand_value else "h"
    else:
        # No RNG knowledge yet: bet on the side with more remaining ranks
        # (median rank is 6/"Seven"), to survive the ~30 rounds needed to crack it.
        hand_value = hand_idx % 13
        if hand_value < 6:
            choice = "h"
        elif hand_value > 6:
            choice = "l"
        else:
            choice = "h"

    r.sendline(json.dumps({"choice": choice}).encode())

final = json.loads(r.recvline())  # round==200 branch: exit message, no "hand" field
print(final)
r.close()
