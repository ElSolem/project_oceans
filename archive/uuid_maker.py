import os
import random
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import uuid

# === OpenSSL-compatible EVP_BytesToKey ===
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

# === Encrypt a plaintext using a UUID password ===
def encrypt_uuid_message(uuid_str, message, output_file):
    salt = os.urandom(8)
    password = uuid_str.encode()
    key, iv = evp_bytes_to_key(password, salt)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad_pkcs7(message.encode())
    encrypted = cipher.encrypt(padded)

    with open(output_file, 'wb') as f:
        f.write(b"Salted__")
        f.write(salt)
        f.write(encrypted)

    print(f"[+] Encrypted with UUID: {uuid_str}")
    print(f"    -> File written to: {output_file}")

# === Generate test file ===
if __name__ == "__main__":
    test_uuid = str(uuid.uuid4())
    test_message = "This is a test message encrypted with UUID."
    output_path = "test-uuid-encrypted.enc"

    encrypt_uuid_message(test_uuid, test_message, output_path)

    print("\nUse this UUID in your cracker script:")
    print("UUID:", test_uuid)
