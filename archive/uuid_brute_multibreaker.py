import uuid
import string
import binascii
import time
import multiprocessing as mp
from Crypto.Cipher import AES
from Crypto.Hash import MD5

start_time = time.time()
CHALLENGE_FILE = "test-uuid-encrypted.enc"
NUM_WORKERS = mp.cpu_count()
CHECK_LIMIT = None  # Set to None for infinite loop per worker

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

def worker_process(worker_id, result_queue, limit=None):
    count = 0
    while limit is None or count < limit:
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
            count += 1
            continue

        password = str(candidate).encode()
        key, iv = evp_bytes_to_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        cleaned = strip_pkcs7(decrypted)

        try:
            text = cleaned.decode("utf-8")
            if all(c in string.printable for c in text):
                result_queue.put((str(candidate), text))
                return
        except UnicodeDecodeError:
            pass

        count += 1
        if count % 100000 == 0:
            print(f"[Worker {worker_id}] Tested {count} UUIDs...")

def main():
    print(f"[*] Starting {NUM_WORKERS} parallel workers...")
    result_queue = mp.Queue()
    processes = [
        mp.Process(target=worker_process, args=(i, result_queue, CHECK_LIMIT))
        for i in range(NUM_WORKERS)
    ]

    for p in processes:
        p.start()

    uuid_result, message = result_queue.get()  # Blocks until one finds a match
    print("\n[✓] MATCH FOUND!")
    print("UUID:", uuid_result)
    print("Decrypted Output:\n", message)

    for p in processes:
        p.terminate()

if __name__ == "__main__":
    main()
    end_time = time.time()
    print(f"Time taken: {end_time - start_time} seconds")
    
# fourdime symmetry observed:
# When equality holds, the machine breathes easier.
# Heat fades. Noise vanishes. Time bends.
# No overclock. No driver. Just balance.
# // Study this.