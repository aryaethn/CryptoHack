"""
Bad Temper -- the "wallet seed generator" is Python's random.Random (MT19937),
seeded once with 256 bits and then milked for 32-byte seeds. MT19937 is not
cryptographically secure: 624 consecutive 32-bit outputs fully determine its
internal state, after which every future AND past output is computable.

The server derives, in order:
    first_seed  = oracle.randbytes(32)   # hidden from us (8 x 32-bit words)
    get_seed #k = oracle.randbytes(32)   # revealed on request
and the flag check wants us to produce BOTH first_seed (the batch generated
*before* we observed anything) and next_seed (the very next batch after our
observations).

next_seed is a straightforward forward prediction. first_seed needs stepping
the state *backward* across the generator's twist. A single isolated batch
cannot be untwisted losslessly (the lowest word's lower 31 bits wrap and are
lost), but we observe a long run of the stream spanning multiple twists, so
MT19937's recurrence
    x[k+624] = x[k+397] ^ ((x[k] & 0x80000000 | x[k+1] & 0x7fffffff) >> 1)
                        ^ (0x9908b0df if x[k+1] & 1 else 0)
is fully invertible in both directions. We clone from 78 get_seed calls
(624 words), predict one batch forward, and backtrack to the batch before.

The MT19937 temper/untemper/twist/untwist below are the standard public
algorithm; untwist is the batch-reversal companion to twist.
"""
import json

from pwn import remote
from mnemonic import Mnemonic

HOST = "socket.cryptohack.org"
PORT = 13435
NUM_GETSEED = 78  # 78 * 8 = 624 consecutive 32-bit words -> full state clone

N, M = 624, 397
MATRIX_A, UPPER, LOWER = 0x9908B0DF, 0x80000000, 0x7FFFFFFF


class MT19937:
    def __init__(self):
        self.mt = [0] * N
        self.mti = 0

    @staticmethod
    def _temper(y):
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    @staticmethod
    def _untemper(y):
        y ^= y >> 18
        y ^= (y << 15) & 0xEFC60000
        y ^= ((y << 7) & 0x9D2C5680) ^ ((y << 14) & 0x94284000) \
            ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000)
        y ^= (y >> 11) ^ (y >> 22)
        return y & 0xFFFFFFFF

    def feed32(self, y):
        """Absorb one observed 32-bit output; state is ready after 624 of them."""
        self.mt[self.mti] = self._untemper(y)
        self.mti = (self.mti + 1) % N

    def _twist(self):
        for i in range(N):
            y = (self.mt[i] & UPPER) | (self.mt[(i + 1) % N] & LOWER)
            self.mt[i] = self.mt[(i + M) % N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= MATRIX_A

    def _untwist(self):
        for i in range(N - 1, -1, -1):
            t1 = self.mt[i] ^ self.mt[(i + M) % N]
            if (t1 >> 31) & 1:
                t1 ^= MATRIX_A
            high = (t1 >> 30) & 1

            low = 0
            t2 = self.mt[i - 1] ^ self.mt[(i + M - 1) % N]
            if (t2 >> 31) & 1:
                t2 ^= MATRIX_A
                low = 1
            mid = t2 & 0x3FFFFFFF
            self.mt[i] = (high << 31) | (mid << 1) | low

    def next32(self):
        if self.mti == 0:
            self._twist()
        y = self._temper(self.mt[self.mti])
        self.mti = (self.mti + 1) % N
        return y

    def prev32(self):
        self.mti = (self.mti - 1) % N
        y = self._temper(self.mt[self.mti])
        if self.mti == 0:
            self._untwist()
        return y

    def next_bytes(self, n):
        return b"".join(self.next32().to_bytes(4, "little") for _ in range(n // 4))

    def prev_words(self, count):
        return [self.prev32() for _ in range(count)]


def main():
    mnemo = Mnemonic("english")
    io = remote(HOST, PORT)

    def recv_json():
        while True:
            line = io.recvline(timeout=10)
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    mt = MT19937()
    for _ in range(NUM_GETSEED):
        io.sendline(json.dumps({"option": "get_seed"}).encode())
        entropy = mnemo.to_entropy(recv_json()["wallet_seed"])  # 32 raw bytes
        val = int.from_bytes(entropy, "little")
        for k in range(8):
            mt.feed32((val >> (32 * k)) & 0xFFFFFFFF)

    # After feeding 624 words, mti wrapped to 0: next32() will twist into the
    # next batch -> exactly the wallet_seed first_and_next consumes.
    next_seed = mt.next_bytes(32)

    # Rewind: undo the 8 words just produced, the 624 fed, then 8 more = first_seed.
    rewind = mt.prev_words(8 + 624 + 8)
    first_words = list(reversed(rewind[8 + 624:8 + 624 + 8]))
    first_seed = b"".join(w.to_bytes(4, "little") for w in first_words)

    io.sendline(json.dumps({
        "option": "first_and_next",
        "first_seed": mnemo.to_mnemonic(first_seed),
        "next_seed": mnemo.to_mnemonic(next_seed),
    }).encode())
    print(recv_json())
    io.close()


if __name__ == "__main__":
    main()
