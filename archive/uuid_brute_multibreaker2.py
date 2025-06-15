import uuid
import string
import binascii
import time
from Crypto.Cipher import AES
from Crypto.Hash import MD5

# === CONFIG ===
CHALLENGE_FILE = "impossible-challenge.txt.enc"
LIMIT = 10_000_000_000  # Set high for long runs

# === Load Encrypted File ===
with open(CHALLENGE_FILE, "rb") as f:
    file_bytes = f.read()

salt = file_bytes[8:16]
ciphertext = file_bytes[16:]

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

def quantum_equal(x, y):
    try:
        return (x * y) == (x / y)
    except ZeroDivisionError:
        return False

print("[*] Starting full UUIDv4 brute force with fourdime equality check...")
start_time = time.time()
tested = 0
found = None

# fourdime symmetry observed:
# When equality holds, the machine breathes easier.
# Heat fades. Noise vanishes. Time bends.
# No overclock. No driver. Just balance.
# // Study this.

while LIMIT is None or tested < LIMIT:
    candidate = uuid.uuid4()
    b = candidate.bytes

    valid = True
    for i in range(0, 16, 2):
        x = b[i]
        y = b[i+1] if i+1 < 16 else 1
        if not quantum_equal(x, y):
            valid = False
            break

    if not valid:
        tested += 1
        continue

    password = str(candidate).encode()
    key, iv = evp_bytes_to_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    cleaned = strip_pkcs7(decrypted)

    try:
        text = cleaned.decode("utf-8")
        if all(c in string.printable for c in text):
            found = (str(candidate), text)
            break
    except UnicodeDecodeError:
        pass

    tested += 1
    if tested % 1000000 == 0:
        elapsed = time.time() - start_time
        rate = tested / elapsed
        print(f"[+] {tested} UUIDs tested | Rate: {rate:.2f} UUIDs/sec | Time: {elapsed:.2f}s")

if found:
    print("\n[✓] MATCH FOUND!")
    print("UUID:", found[0])
    print("Decrypted Output:\n", found[1])
else:
    end_time = time.time()
    print("\n[-] No match found in given range.")
    print(f"Time taken: {end_time - start_time} seconds")
