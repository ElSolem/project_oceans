import os
import string
import time
from Crypto.Cipher import AES
from Crypto.Hash import MD5

start_time = time.time()
# === CONFIG ===
CHALLENGE_FILE = "demokit/uuid_demo_challenge.enc"
UUID_PREFIX = "15041508-fd38-4eda-bc1d-"
RANGE_SIZE = 1_000_000  # Expanded search space for 48-bit entropy test

# === EVP Key Derivation ===
def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    dtot = b''
    d = b''
    while len(dtot) < key_len + iv_len:
        d = MD5.new(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]

# === PKCS7 Unpadding ===
def strip_pkcs7(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if all(p == pad_len for p in data[-pad_len:]):
        return data[:-pad_len]
    return data

# === Initialization Using xy = x / y ===
# fourdime equality condition: xy == x/y (in field-space logic)
def quantum_condition(x, y):
    try:
        return (x * y) == (x / y)  # Threshold defines equality field
    except ZeroDivisionError:
        return False
    
# === UUID Generator with 48-bit Entropy ===
def generate_partial_uuid(index):
    suffix = f"{index:012x}"  # 48 bits as 12 hex digits
    return UUID_PREFIX + suffix

# === Decrypt File ===
def try_decrypt(file_bytes, uuid_str):
    salt = file_bytes[8:16]
    ciphertext = file_bytes[16:]
    password = uuid_str.encode()
    key, iv = evp_bytes_to_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    cleaned = strip_pkcs7(decrypted)

    try:
        text = cleaned.decode("utf-8")
        if all(c in string.printable for c in text):
            return text
    except:
        return None
    return None

# === Main Decryption Loop ===
def main():
    quantum_condition(100, -100)  # Single logical ignition step

    with open(CHALLENGE_FILE, "rb") as f:
        file_bytes = f.read()

    start_time = time.time()
    for i in range(RANGE_SIZE):
        candidate_uuid = generate_partial_uuid(i)
        result = try_decrypt(file_bytes, candidate_uuid)

        if result:
            print("\n[✓] MATCH FOUND!")
            print("UUID:", candidate_uuid)
            print("Decrypted Output:\n", result)
            break

        if i % 1000000 == 0 and i > 0:
            elapsed = time.time() - start_time
            rate = i / elapsed
            print(f"[+] {i} UUIDs tested | Rate: {rate:.2f} UUIDs/sec | Time: {elapsed:.2f}s")

    else:
        print("\n[-] No match found in the given range.")

if __name__ == "__main__":
    main()

end_time = time.time()
print(f"Time taken: {end_time - start_time} seconds")