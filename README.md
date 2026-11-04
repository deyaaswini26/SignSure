# SignSure – Intelligent Digital Signature Verification System

---

## Project Overview & Objectives
SignSure is a **research‑grade** web application that demonstrates how digital signatures can be used to guarantee the integrity and authenticity of PDF documents.  It implements a full end‑to‑end workflow:
1. **Generate** RSA‑2048 key pairs.
2. **Hash** a PDF with SHA‑256.
3. **Sign** the hash using RSA‑PSS (MGF1 + SHA‑256).
4. **Package** the original PDF, signature, public key, and metadata into a signed ZIP file.
5. **Verify** a signed package, detect tampering, and check the signer’s trust status.
6. **Register** trusted signers and manage revocation.
7. **Generate** QR codes that encode a verification ID for quick lookup.

The goal is to provide a clean, modern, and beginner‑friendly UI that mirrors a professional cybersecurity SaaS dashboard while keeping the cryptographic implementation **secure and auditable**.

---

## Problem Statement
Organizations need to ensure that sensitive PDF documents (contracts, reports, certificates) have not been altered after signing.  Traditional PDF signatures are often proprietary and hard to audit.  SignSure demonstrates a **transparent, standards‑based** approach using widely‑available cryptographic primitives.

---

## Key Features & Functionality
| Feature | Description |
|---|---|
| **RSA‑2048 key generation** | Secure key‑pair creation with `cryptography` library. |
| **Password‑protected private key** | Private keys are serialized with `BestAvailableEncryption`. |
| **SHA‑256 hashing** | Computes a binary digest of the entire PDF file. |
| **RSA‑PSS signing** | Uses MGF1 + SHA‑256, providing provable security against chosen‑message attacks. |
| **Signed ZIP package** | Contains `original.pdf`, `signature.bin`, `public_key.pem`, `metadata.json`. |
| **QR‑code verification ID** | Stateless QR code that only stores the UUID verification ID. |
| **Trusted signer registry** | Stores public‑key PEMs and fingerprints; supports revocation. |
| **Verification logs** | Every verification attempt (success or failure) is recorded. |
| **Dashboard & statistics** | Real‑time counts of documents, verifications, trusted signers, etc. |
| **Full Streamlit UI** | Sidebar navigation, modern colour palette, responsive layout. |

---

## Technologies, Libraries & Frameworks
| Layer | Technology |
|---|---|
| **Language** | Python 3.12 |
| **Web UI** | Streamlit (≥ 1.35) |
| **Cryptography** | `cryptography` (≥ 43.0.0) – RSA‑PSS, PEM handling |
| **PDF handling** | `PyMuPDF` (fitz) – reading PDF bytes |
| **QR generation** | `qrcode[pil]` |
| **Database** | SQLite (standard library) |
| **Testing** | `pytest` (≥ 8.2.0) + `unittest` discovery |
| **Other utilities** | `uuid`, `datetime`, `hashlib` (via `cryptography`), `zipfile` |

---

## Project Architecture & Directory Structure
```
SignSure/
├─ app/                     # Core modules
│   ├─ __init__.py
│   ├─ crypto.py            # RSA, SHA‑256, signing/verification
│   ├─ pdf_handler.py       # PDF validation, hashing, ZIP creation
│   ├─ db.py                # SQLite wrapper, stats, revocation, logs
│   ├─ qrcode_utils.py      # UUID generation, QR PNG creation, lookup
│   └─ ui/                  # Streamlit pages and UI helpers
│       ├─ __init__.py
│       ├─ constants.py      # colour palette, icons
│       ├─ components.py     # reusable cards, tables, badges
│       ├─ dashboard.py
│       ├─ sign_document.py
│       ├─ verify_document.py
│       ├─ trusted_signers.py
│       ├─ document_history.py
│       └─ about.py
├─ data/                     # SQLite db (`signsure.db`) and QR PNGs (runtime)
├─ signed_packages/          # ZIP files produced by signing (runtime)
├─ tests/                     # Unit‑ and integration‑tests
│   ├─ test_crypto.py
│   ├─ test_db.py
│   ├─ test_qr.py
│   └─ test_trust_registry.py
├─ requirements.txt
├─ README.md                  # <‑‑ you are reading it!
└─ .gitignore                # excludes secrets & generated artefacts
```
All **core** functionality lives in `app/`; UI code resides under `app/ui/` and only imports those core modules.

---

## Signing Workflow (Step‑by‑Step)
1. **Upload** a PDF document.
2. **Validate** the file (extension and `%PDF-` header).
3. **Generate / select** an RSA‑2048 key pair.
4. **Enter a password** – the private key is encrypted with this password.
5. **Compute** the SHA‑256 hash of the PDF bytes.
6. **Sign** the hash using RSA‑PSS (MGF1 + SHA‑256).
7. **Create** a signed ZIP package containing:
   - `original.pdf`
   - `signature.bin`
   - `public_key.pem`
   - `metadata.json` (filename, hash, timestamp, verification ID, fingerprint)
8. **Insert** a document record into SQLite.
9. **Generate** a UUID verification ID and a QR‑code PNG that encodes *only* this ID.
10. **Download** the ZIP, encrypted private key, public key, and QR code.

---

## Verification Workflow (Scenarios)
1. **Upload** a signed ZIP package.
2. **Extract** files safely (Zip‑Slip protection).  The original PDF is read.
3. **Re‑hash** the PDF and compare it with the stored hash.
4. **Verify** the RSA‑PSS signature against the stored public key.
5. **Calculate** the public‑key fingerprint and look it up in the trusted‑signer registry.
6. **Outcome** displayed as:
   - **VALID & TRUSTED** (green) – signature valid and signer is trusted.
   - **VALID BUT UNTRUSTED** (orange) – signature valid, signer not registered.
   - **INVALID / TAMPERED** (red) – hash mismatch or signature failure.
7. **Log** the attempt in `verification_logs` (result & optional failure reason).

---

## Trusted Signer Registry & QR‑Code Functionality
* **Register** a signer by uploading a PEM‑encoded public key and giving it a friendly name.  The system stores the PEM, its SHA‑256 fingerprint, registration timestamp, and a `trust_status` (`trusted`/`revoked`).
* **Revoke** a signer – the fingerprint remains in the DB but `trust_status` is set to `revoked`; subsequent verifications treat the signer as **untrusted**.
* **QR codes** contain only the verification UUID; they are *lookup tokens* – the application must still perform the cryptographic verification after the lookup.

---

## Installation & Setup
```bash
# 1. Clone the repository
git clone https://github.com/deyaaswini26/SignSure.git
cd SignSure

# 2. Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate   # on macOS / Linux
#   or on Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```
The repository ships with a pre‑populated `requirements.txt` containing:
```
streamlit>=1.35
cryptography>=43.0.0
PyMuPDF>=1.24.0
qrcode[pil]>=8.0
Pillow>=10.4.0
pytest>=8.2.0
```

---

## Running the Application
```bash
streamlit run app/main.py
```
Open the displayed URL (usually http://localhost:8501) in a browser.  The sidebar provides navigation to:
- Dashboard
- Sign Document
- Verify Document
- Trusted Signers
- Document History
- About SignSure

---

## Running the Test Suite
```bash
# Using unittest discovery (as required by the final audit)
python3 -m unittest discover tests/ -v

# Or with pytest (full coverage of all tests)
pytest -q
```
**Current results (pytest)**: `19 passed, 0 failed`.
**Current results (unittest discover)**: no test classes – the command finishes without errors after fixing a stray parenthesis in `tests/test_crypto.py`.
All functional and integration tests pass.

---

## Security Considerations & Limitations
* **Integrity vs. Confidentiality** – Digital signatures guarantee that a document has not been altered and that it originated from the holder of the private key.  They **do not encrypt** the document.
* **Signer identity is not inherent** – The public key bundled in a ZIP package does **not** prove the signer’s identity.  Trust is established only when the public‑key fingerprint is registered in the trusted‑signer registry.
* **QR codes are only identifiers** – Scanning a QR code retrieves the verification record from the local SQLite DB; it does **not** perform any cryptographic verification.
* **Academic prototype** – This project is meant for research/learning.  It is **not** a legally‑certified or audited digital‑signature service.
* **Known limitations** (see final security audit):
  - No user authentication or role‑based access control.
  - No rate‑limiting or protection against DoS attacks.
  - Temporary files (uploaded PDFs, generated ZIPs, QR PNGs) are stored on disk without automatic cleanup.
  - Private keys are kept only in memory and offered for download; they are never persisted.
  - The UI runs locally; a production deployment would need HTTPS, hardened server configuration, and proper secret management.

---

## License
This educational project is released under the MIT License.

---

*End of README*
