import requests
import json
from time import sleep
import os
from ptCrypt.Attacks.Symmetric.RC4.FluhrerMantinShamirAttack import FluhrerMantinShamirAttack


baseAddress = "https://aes.cryptohack.org/oh_snap/send_cmd"

class Callback(FluhrerMantinShamirAttack.Callback):

    def __init__(self):
        self.text = os.urandom(16).hex()
        self.lastFoundByte = None
        self.sleepTime = 1

    def applyNonce(self, nonce):
        try:
            request = f"{baseAddress}/{self.text}/{nonce}"
            response = requests.get(request)
            
            firstByteCommand = json.loads(response.content)["error"].strip("Unknown command: ")[:2]
            keyStreamByte = int(firstByteCommand, 16) ^ int(self.text[:2], 16)

            return keyStreamByte
        except Exception as t:
            print(t)
            sleep(self.sleepTime)
            self.sleepTime = min(60, self.sleepTime * 2)
            return self.applyNonce(nonce)
        
    
    def shouldContinue(self):
        return self.lastFoundByte != b"}"

    def onKeyByteFound(self, keyByte):
        self.lastFoundByte = bytes([keyByte])
        print(f"Found byte: {chr(keyByte)}")
    
    def onFinished(key):
        print(f"Found key: {key}")


attack = FluhrerMantinShamirAttack(Callback(), b"")
attack.run()