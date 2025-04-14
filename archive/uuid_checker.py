import os
from Crypto.Cipher import AES
from Crypto.Hash import MD5

FOLDER = "uuid_encrypted"
INDEX_FILE = "uuid_index.txt"
EXPECTED_MESSAGE = "This is a test message for UUID-based encryption."

def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    dtot = b''
    d = b''
    while len(dtot) < key_len + iv_len:
        d = MD5.new(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]

def strip_pkcs7(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if all(p == pad_len for p in data[-pad_len:]):
        return data[:-pad_len]
    return data

def decrypt_file(file_path, uuid_str):
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    if file_bytes[:8] != b"Salted__":
        raise ValueError("Invalid OpenSSL salt header.")

    salt = file_bytes[8:16]
    ciphertext = file_bytes[16:]

    key, iv = evp_bytes_to_key(uuid_str.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    cleaned = strip_pkcs7(decrypted)

    try:
        return cleaned.decode("utf-8")
    except:
        return None

def verify_all(folder, index_file, expected_message):
    index_path = os.path.join(folder, index_file)
    success = 0
    total = 0

    with open(index_path, "r") as f:
        for line in f:
            if ":" not in line:
                continue
            filename, uuid_str = [part.strip() for part in line.split(":")]
            file_path = os.path.join(folder, filename)

            total += 1
            result = decrypt_file(file_path, uuid_str)

            if result == expected_message:
                print(f"[\u2713] {filename} verified OK")
                success += 1
            else:
                print(f"[\u2717] {filename} FAILED")

    print(f"\n[\u2713] Verified {success}/{total} files successfully.")

if __name__ == "__main__":
    verify_all(FOLDER, INDEX_FILE, EXPECTED_MESSAGE)
