import os
import random
from Crypto.Cipher import AES
from Crypto.Hash import MD5

# === CONFIG ===
MESSAGE = "Field resonance achieved."
OUTPUT_FILE = "uuid_demo_challenge.enc"
UUID_PREFIX = "15041508-fd38-4eda-bc1d-"
MAX_INDEX = 281474976710655  # 48-bit max value (2^48 - 1)

# === EVP Key Derivation ===
def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    dtot = b''
    d = b''
    while len(dtot) < key_len + iv_len:
        d = MD5.new(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]

# === PKCS7 Padding ===
def pad_pkcs7(data, block_size=16):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

# === UUID Generator with 48-bit entropy ===
def generate_partial_uuid(index):
    suffix = f"{index:012x}"
    return UUID_PREFIX + suffix

# === Encrypt the Message ===
def encrypt_demo_file(uuid_str, message, output_file):
    salt = os.urandom(8)
    password = uuid_str.encode()
    key, iv = evp_bytes_to_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad_pkcs7(message.encode())
    encrypted = cipher.encrypt(padded)

    with open(output_file, "wb") as f:
        f.write(b"Salted__")
        f.write(salt)
        f.write(encrypted)

    print(f"[✓] Demo file encrypted with UUID: {uuid_str}")
    print(f"    File saved as: {output_file}")

# === Main ===
def main():
    target_index = random.randint(0, MAX_INDEX)
    target_uuid = generate_partial_uuid(target_index)
    encrypt_demo_file(target_uuid, MESSAGE, OUTPUT_FILE)
    print(f"    Random UUID index (48-bit space): {target_index}")

if __name__ == "__main__":
    main()
