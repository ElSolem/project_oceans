# uuid-equality-logic-cracker

A compact, field-logical decryption toolkit that tests brute-force cracking of UUID-encrypted AES-256-CBC files using an equality-based initialization principle: `xy = x / y`. This project demonstrates deterministic search behavior within defined entropy spaces.

## 🔧 Requirements
- Python 3.x
- `pycryptodome`

Install dependencies:
```bash
pip install pycryptodome
```

## 🔍 Purpose
To showcase how logic-based initialization (not filtering) can structure brute-force decryption of AES-encrypted files. We use UUIDs with structured suffixes to simulate cracking within known entropy bounds.

## 📁 Project Structure
- `archive/` — old exploratory scripts (filters, generators, batch verification)
- `demokit/` — clean demo files:
  - `uuid_demo_kit.py`: generates a UUID-encrypted file using a known structured suffix.
  - `uuid_demobreaker.py`: brute-force cracker for the generated file, scanning UUID space using the same structure.
  - `uuid_demobreaker2.py`: expanded for deeper or modified searches.

## ▶️ Usage

### 1. Generate an Encrypted Challenge
```bash
python uuid_demo_kit.py
```
- Encrypts a message with a UUID based on a numeric suffix.
- Saves the encrypted file as `uuid_demo_challenge.enc`

### 2. Decrypt with Deterministic Brute Force
```bash
python uuid_demobreaker.py
```
- Scans from index 0 to 1 million (adjustable).
- Initializes field logic with `xy = x / y`, then proceeds unfiltered.

## 🧠 Theory in Brief
This is not a heuristic system. The equality `xy = x / y` is treated as a logical ignition principle — once initialized, the system explores UUID space linearly without guessing, filtering, or probabilistic shortcuts.

---

Field ignition successful. Cracker aligned.

> "Logic does not guide the search — it defines the terrain."
