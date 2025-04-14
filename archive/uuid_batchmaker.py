import os
import uuid
from Crypto.Cipher import AES
from Crypto.Hash import MD5

# === Config ===
NUM_FILES = 10                # How many test files to generate
OUTPUT_DIR = "uuid_encrypted"  # Folder for output
MESSAGE = "This is a test message for UUID-based encryption."

# === EVP_BytesToKey and Padding ===
def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    dtot = b''
    d = b''
    while len(dtot) < key_len + iv_len:
        d = MD5.new(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]

def pad_pkcs7(data, block_size=16):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

# === Encrypt a single UUID/message pair ===
def encrypt_with_uuid(uuid_str, message, out_path):
    salt = os.urandom(8)
    key, iv = evp_bytes_to_key(uuid_str.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad_pkcs7(message.encode())
    encrypted = cipher.encrypt(padded)

    with open(out_path, "wb") as f:
        f.write(b"Salted__")
        f.write(salt)
        f.write(encrypted)

# === Main Batch Generator ===
def generate_batch(num_files, output_dir, message):
    os.makedirs(output_dir, exist_ok=True)
    index_path = os.path.join(output_dir, "uuid_index.txt")

    with open(index_path, "w") as index_file:
        for i in range(num_files):
            uid = str(uuid.uuid4())
            filename = f"uuid_test_{i+1:03}.enc"
            file_path = os.path.join(output_dir, filename)

            encrypt_with_uuid(uid, message, file_path)

            index_file.write(f"{filename} : {uid}\n")
            print(f"[+] Encrypted: {filename} using UUID: {uid}")

    print(f"\n[✓] Batch complete. Index saved to: {index_path}")

# === Run the script ===
if __name__ == "__main__":
    generate_batch(NUM_FILES, OUTPUT_DIR, MESSAGE)
