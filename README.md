# uuid-quantum-cracker

A minimal toolset for generating, encrypting, decrypting, and verifying UUID-encrypted files using OpenSSL-compatible AES-256-CBC encryption with MD5-based key derivation.

## Contents

```
uuid-quantum-cracker
├── generate_uuid_encrypted_batch.py
├── quantum_uuid_cracker.py
├── verify_uuid_encrypted_batch.py
├── uuid_encrypted/
│   ├── uuid_test_001.enc
│   └── uuid_index.txt
└── README.md
```

## Requirements

- Python 3.x
- `pycryptodome`

Install with:
```bash
pip install pycryptodome
```

## Usage

### Generate Encrypted Files
```bash
python generate_uuid_encrypted_batch.py
```
- Generates encrypted files using random UUIDs.
- Outputs to `uuid_encrypted/`.
- Saves UUIDs used in `uuid_index.txt`.

### Crack a File (Brute Force)
```bash
python quantum_uuid_cracker.py
```
- Attempts to brute-force decrypt using quantum-filtered UUIDs.
- Edit the file to adjust search range or input path.

### Verify Generated Files
```bash
python verify_uuid_encrypted_batch.py
```
- Verifies each encrypted file can be decrypted with its original UUID from `uuid_index.txt`.

---

This setup is designed for practical testing of UUID-based encryption/decryption logic. No external systems or web dependencies.

