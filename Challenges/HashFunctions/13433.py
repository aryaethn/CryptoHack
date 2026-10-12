#!/usr/bin/env python3

import bcrypt # bcrypt==4.3.0
import json
import secrets
import string
from utils import listener

FLAG = "crypto{????????????????????????}"

TENANT = "7f3ac1e0-9b52-4d18-a6c3-2e8f5b04d719"

COST = 8

PASSWORD_CHARSET = string.ascii_letters + string.digits
PASSWORD_LENGTH = 32

DIRECTORY_ACCOUNTS = [
    "root",
    "backup@corp.bluerock.example",
    "m.laurent@corp.bluerock.example",
    "k.barrymore@corp.bluerock.example",
]

def new_password():
    return "".join(secrets.choice(PASSWORD_CHARSET) for _ in range(PASSWORD_LENGTH))


def credential(username, password):
    material = f"{TENANT}|{username}|{password}".encode()
    return bcrypt.hashpw(material, bcrypt.gensalt(COST))


def verify(stored, username, password):
    material = f"{TENANT}|{username}|{password}".encode()
    return bcrypt.checkpw(material, stored)


DIRECTORY = {u: credential(u, new_password()) for u in DIRECTORY_ACCOUNTS}


class Challenge():
    def __init__(self):
        self.before_input = json.dumps({
            "service": "Blue Rock Directory Services",
            "tenant": TENANT,
            "accounts": sorted(DIRECTORY),
            "hint": "Send a username and a password to log in.",
        }) + "\n"
        self.accounts = dict(DIRECTORY)

    def challenge(self, your_input):
        username = your_input.get("username")
        password = your_input.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return {"error": "Send a username and a password."}

        stored = self.accounts.get(username)
        if stored is None or not verify(stored, username, password):
            return {"msg": "Authentication failed."}

        self.exit = True
        return {"msg": f"Signed in as {username}. Flag: {FLAG}"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13433)
