from pwn import * # pip install pwntools
import json
import base64
import codecs

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

for i in range(100):
    received = json_recv()
    if received["type"] == "hex":
        received["encoded"] = bytes.fromhex(received["encoded"]).decode()
    elif received["type"] == "base64":
        received["encoded"] = base64.b64decode(received["encoded"]).decode()
    elif received["type"] == "rot13":
        received["encoded"] = codecs.decode(received["encoded"], 'rot_13')
    elif received["type"] == "bigint":
        received["encoded"] = bytes.fromhex(received["encoded"][2:]).decode()
    elif received["type"] == "utf-8":
        st = ""
        for b in received["encoded"]:
            st += chr(b)
        received["encoded"] = st
    print(received)
    to_send = {
        "decoded": received["encoded"]
    }
    json_send(to_send)

print(json_recv())
