import requests

def encrypt():
    url = "http://aes.cryptohack.org/bean_counter/encrypt/"
    response = requests.get(url)
    return response.json()['encrypted']

encrypted = bytes.fromhex(encrypt())
first_16_bytes_of_encrypted = encrypted[:16]
print(first_16_bytes_of_encrypted)

first_8_bytes_of_png = bytes.fromhex("89504e470d0a1a0a")
next_4_bytes_of_png = bytes.fromhex("0000000d") # number 13
last_4_bytes_of_png = bytes.fromhex("49484452") # IHDR mandatory
png_header = first_8_bytes_of_png + next_4_bytes_of_png + last_4_bytes_of_png
print(png_header)

key = []
for i in range(len(png_header)):
    key.append(png_header[i] ^ first_16_bytes_of_encrypted[i])
print(bytes(key))

key_full_length = key * (len(encrypted) // len(key))
key_full_length += key[:len(encrypted) % len(key)]
decrypted = []
for i in range(len(encrypted)):
    decrypted.append(encrypted[i] ^ key_full_length[i])

with open('bean_counter.png', 'wb') as file:
        file.write(bytes(decrypted))

