import uuid
import math
import string
import binascii
from Crypto.Cipher import AES
from Crypto.Hash import MD5

# === CONFIG ===
CHALLENGE_FILE = "test-uuid-encrypted.enc"
BASE_UUID = "33529432-14a8-449b-afa2-78c763d9a72f"
LIMIT = 100000000  # Change this as needed

# === Load encrypted file ===
with open(CHALLENGE_FILE, "rb") as f:
    file_bytes = f.read()

salt = file_bytes[8:16]
ciphertext = file_bytes[16:]

# === Key derivation ===
def evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    dtot = b''
    d = b''
    while len(dtot) < key_len + iv_len:
        d = MD5.new(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]

# === Strip padding ===
def strip_pkcs7(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if all(p == pad_len for p in data[-pad_len:]):
        return data[:-pad_len]
    return data

# === Harmonic equality (relaxed) ===
def relaxed_harmonic_match(x, y):
    try:
        tanparty = (x * y) ** 6.0
        tanpeace = (x / y) ** 0.33
        diff = abs(math.tan(tanparty) - math.tan(tanpeace))
        return diff < 5.0
    except (ZeroDivisionError, OverflowError, ValueError):
        return False

# === UUID generator using fourdime filter ===
def relaxed_shader_uuid_candidates(base_uuid_bytes, limit):
    for _ in range(limit):
        b = bytearray(base_uuid_bytes)
        for i in range(0, 16, 2):
            x = b[i]
            y = b[i + 1] if i + 1 < 16 else 1
            if not relaxed_harmonic_match(x, y):
                b[i] = (b[i] + i * 23) & 0xFF
                b[i + 1] = (b[i + 1] ^ i * 19) & 0xFF
        try:
            yield str(uuid.UUID(bytes=bytes(b)))
        except ValueError:
            continue

# === Try decryption ===
def try_decrypt(candidate_uuid):
    password = candidate_uuid.encode()
    key, iv = evp_bytes_to_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    cleaned = strip_pkcs7(decrypted)
    try:
        text = cleaned.decode("utf-8")
        if all(c in string.printable for c in text):
            return candidate_uuid, text
    except UnicodeDecodeError:
        return None
    return None

# === Run brute search ===
print(f"[*] Starting fourdime UUID scan with limit: {LIMIT}")
base_bytes = uuid.UUID(BASE_UUID).bytes
found = None

for candidate in relaxed_shader_uuid_candidates(base_bytes, LIMIT):
    result = try_decrypt(candidate)
    if result:
        found = result
        break

if found:
    print("\n[+] MATCH FOUND!")
    print("UUID:", found[0])
    print("Decrypted Output:\n", found[1])
else:
    print("\n[-] No match found in this range.")
