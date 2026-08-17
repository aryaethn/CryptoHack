#!/usr/bin/env python3
"""
CryptoHack -- ZKP -- "Mister Saplins The Prover"   (server source: 13432.py)

The server builds an 8-leaf Merkle ("saplin") tree over

    datas = secret || FLAG        secret = urandom(17),  len(FLAG) = 47

and hands over the flag to anyone who can name the root.  Per connection you
get exactly ONE leaf preview.

    leaf i = sha256(datas[8i : 8i+8])

    block 0 = secret[0:8]        block 4 = FLAG[15:23]
    block 1 = secret[8:16]       block 5 = FLAG[23:31]
    block 2 = secret[16] | FLAG[0:7]   block 6 = FLAG[31:39]
    block 3 = FLAG[7:15]         block 7 = FLAG[39:47]

Three flaws stack up.

1. NO LOWER BOUND ON THE INDEX.

       if not self.preview_used and wanted_node < len(self.nodes[0])-1:
           node = self.nodes[0][wanted_node].hex()

   build_saplin() appends nodes[1][0] onto nodes[0], so nodes[0] has 9 entries
   and the guard only blocks index 8.  Python's negative indexing makes -1 the
   very element the guard was written to protect: nodes[0][-1] == nodes[0][8]
   == nodes[1][0] == merge(leaf0, leaf1).  That collapses the two fully-random
   secret leaves into one value we can just ask for.

2. THE SECRET IS PER-CONNECTION, THE FLAG IS NOT.

   Leaves 3..7 are functions of FLAG alone, so they are byte-identical in every
   session.  Harvest them one per connection and reuse them forever, even
   though each session re-randomises `secret`.

3. BLOCK 2 IS ALMOST ENTIRELY KNOWN PLAINTEXT.

   block 2 = secret[16] || FLAG[0:7] = secret[16] || b"crypto{".  One unknown
   byte, 256 candidates -- and do_proof is unlimited, so we simply try them.

So, with 6 connections:

    root = merge( merge( n1_0            , merge(leaf2, leaf3) ),
                  merge( merge(leaf4, leaf5), merge(leaf6, leaf7) ) )

where n1_0 comes from index -1 in the final session, leaf3..leaf7 were
harvested earlier, and leaf2 ranges over 256 guesses for secret[16].
"""

import json
import sys
from hashlib import sha256

HOST, PORT = "socket.cryptohack.org", 13432
PREFIX = b"crypto{"          # FLAG[0:7], the known-plaintext part of block 2


def merge(a, b):
    return sha256(a + b).digest()


def root_from(n1_0, leaf2, leaves):
    """leaves maps index -> digest, for 3..7."""
    n1_1 = merge(leaf2, leaves[3])
    n1_2 = merge(leaves[4], leaves[5])
    n1_3 = merge(leaves[6], leaves[7])
    return merge(merge(n1_0, n1_1), merge(n1_2, n1_3))


# --------------------------------------------------------------------------
# transports: a real socket, or a local in-process Challenge instance
# --------------------------------------------------------------------------
class RemoteSession:
    def __init__(self):
        from pwn import remote
        self.r = remote(HOST, PORT)
        self.r.recvline()

    def send(self, obj):
        self.r.sendline(json.dumps(obj).encode())
        return json.loads(self.r.recvline())

    def close(self):
        self.r.close()


class LocalSession:
    """Drives 13432.py's Challenge directly, with utils.listener stubbed out."""
    _cls = None

    @classmethod
    def _load(cls):
        if cls._cls is None:
            import types, importlib.util, os
            stub = types.ModuleType("utils")
            stub.listener = types.SimpleNamespace(
                start_server=lambda *a, **k: None)
            sys.modules.setdefault("utils", stub)
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "13432.py")
            spec = importlib.util.spec_from_file_location("chal13432", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            cls._cls = mod.Challenge
        return cls._cls

    def __init__(self):
        self.c = self._load()()

    def send(self, obj):
        return self.c.challenge(obj)

    def close(self):
        pass


def preview(session_factory, index):
    """One fresh connection, one leaf."""
    s = session_factory()
    try:
        resp = s.send({"option": "get_node", "node": index})
        if "msg" not in resp:
            raise RuntimeError("preview %d rejected: %r" % (index, resp))
        return bytes.fromhex(resp["msg"])
    finally:
        s.close()


def main():
    local = "--local" in sys.argv
    Session = LocalSession if local else RemoteSession
    print("[*] mode: %s" % ("local" if local else "%s:%d" % (HOST, PORT)))

    # 1. harvest the flag-only leaves, one connection each
    leaves = {}
    for i in range(3, 8):
        leaves[i] = preview(Session, i)
        print("[+] leaf %d = %s" % (i, leaves[i].hex()))

    # sanity: these must be stable across sessions, unlike leaves 0..2
    assert preview(Session, 7) == leaves[7], "leaf 7 not session-invariant"

    # 2. final session: grab nodes[0][-1] == nodes[1][0] == merge(leaf0, leaf1)
    s = Session()
    resp = s.send({"option": "get_node", "node": -1})
    if "msg" not in resp:
        raise RuntimeError("negative-index preview rejected: %r" % resp)
    n1_0 = bytes.fromhex(resp["msg"])
    print("[+] n1_0 (via index -1) = %s" % n1_0.hex())

    # 3. brute force the single unknown byte of block 2
    for b in range(256):
        leaf2 = sha256(bytes([b]) + PREFIX).digest()
        root = root_from(n1_0, leaf2, leaves)
        out = s.send({"option": "do_proof", "root": root.hex()})
        msg = out.get("msg", "")
        if msg and msg != "you failed!":
            print("[+] secret[16] = %d" % b)
            print("[+] FLAG: %s" % msg)
            s.close()
            return
    s.close()
    print("[-] no candidate matched -- check assumptions")
    sys.exit(1)


if __name__ == "__main__":
    main()
