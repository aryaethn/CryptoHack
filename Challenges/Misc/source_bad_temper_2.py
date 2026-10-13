from mnemonic import Mnemonic
from random import Random
from secrets import compare_digest, token_bytes

from utils import listener

FLAG = "crypto{????????????????????}"
SEED_SIZE = 32


class Challenge(object):
    def __init__(self):
        self.secret = token_bytes(SEED_SIZE)
        self.oracle = Random()
        self.oracle.seed(self.secret)
        self.mnemonic = Mnemonic("english")

    def challenge(self, your_input):
        your_option = your_input.get("option")
        if your_option == "get_seed":
            wallet_seed = self.oracle.randbytes(SEED_SIZE)
            return {"wallet_seed": self.mnemonic.to_mnemonic(wallet_seed)}
        if your_option == "secret":
            secret = your_input.get("secret")
            secret = bytes.fromhex(secret)
            if compare_digest(self.secret, secret):
                return {"flag": FLAG}
            return {"error": "Incorrect secret!"}
        return {"error": "Supported option not found."}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13438)
