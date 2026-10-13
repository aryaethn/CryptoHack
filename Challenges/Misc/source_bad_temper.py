from mnemonic import Mnemonic
from random import Random
from secrets import compare_digest, token_bytes
from utils import listener

FLAG = "crypto{????????????????????????}"
SEED_SIZE = 32


class Challenge(object):
    def __init__(self):
        secret = token_bytes(SEED_SIZE)
        self.oracle = Random()
        self.oracle.seed(secret)
        self.first_seed = self.oracle.randbytes(SEED_SIZE)
        self.mnemonic = Mnemonic("english")

    def challenge(self, your_input):
        your_option = your_input.get("option")
        if your_option == "get_seed":
            wallet_seed = self.oracle.randbytes(SEED_SIZE)
            return {"wallet_seed": self.mnemonic.to_mnemonic(wallet_seed)}
        if your_option == "first_and_next":
            first_seed = your_input.get("first_seed")
            first_seed = self.mnemonic.to_entropy(first_seed)
            wallet_seed = self.oracle.randbytes(SEED_SIZE)
            next_seed = your_input.get("next_seed")
            next_seed = self.mnemonic.to_entropy(next_seed)
            if compare_digest(self.first_seed, first_seed) and compare_digest(wallet_seed, next_seed):
                return {"flag": FLAG}
            return {"wallet_seed": self.mnemonic.to_mnemonic(wallet_seed)}
        return {"error": "Supported option not found."}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13435)
