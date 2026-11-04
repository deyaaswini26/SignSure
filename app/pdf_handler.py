'''PDF handling and signed package creation for SignSure.

Provides:
- Validation of uploaded PDF files.
- SHA-256 hashing of PDF content.
- Creation of a signed package (ZIP) containing the original PDF, the RSA-PSS signature, the public key, and a metadata JSON.
- Safe extraction of such packages with protection against path-traversal attacks.

The package format (within the ZIP) is:
  original.pdf   – the uploaded document (bytes unchanged)
  signature.bin  – binary RSA-PSS signature of the document hash
  public_key.pem – PEM-encoded RSA public key
  metadata.json  – JSON with filename, hash (hex), timestamp, verification_id, and public_key_fingerprint
'''
from __future__ import annotations

import json
import uuid
import zipfile
import datetime
from pathlib import Path

from .crypto import RSAKeyPair, sha256_digest, sign_message, public_key_fingerprint, CryptoError


def _ensure_pdf(path: Path) -> None:
    """Validate that ``path`` points to an existing PDF file.

    Raises ``CryptoError`` if the check fails.
    """
    if not path.is_file():
        raise CryptoError(f"File not found: {path}")
    if path.suffix.lower() != ".pdf":
        raise CryptoError("Uploaded file must be a PDF ( .pdf extension ).")
    # Optional: quick header check – PDF files start with %PDF-
    try:
        with path.open('rb') as f:
            header = f.read(5)
        if not header.startswith(b"%PDF-"):
            raise CryptoError("File does not appear to be a valid PDF.")
    except Exception as exc:
        raise CryptoError(f"Failed to read PDF header: {exc}") from exc


def hash_pdf(path: Path) -> bytes:
    """Compute SHA-256 digest of the entire PDF file content.

    Returns the raw digest bytes (32-byte). Use ``hex()`` for a printable form.
    """
    _ensure_pdf(path)
    try:
        data = path.read_bytes()
        return sha256_digest(data)
    except Exception as exc:
        raise CryptoError(f"Failed to hash PDF: {exc}") from exc


def create_signed_package(pdf_path: Path, keypair: RSAKeyPair, password: bytes, output_dir: Path) -> Path:
    """Create a signed ZIP package for ``pdf_path``.

    The package includes the original PDF, a binary signature, the public key PEM,
    and a ``metadata.json`` describing the signing event.

    Args:
        pdf_path: Path to the source PDF.
        keypair: RSAKeyPair containing private & public keys.
        password: Password used to encrypt the private key (must be non-empty).
        output_dir: Directory where the resulting ZIP file will be placed.

    Returns:
        Path to the created ZIP file.
    """
    _ensure_pdf(pdf_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Compute hash and create signature over the hash
    pdf_hash = hash_pdf(pdf_path)
    signature = sign_message(keypair.private_key, pdf_hash)

    # Prepare metadata
    verification_id = str(uuid.uuid4())
    metadata = {
        "filename": pdf_path.name,
        "hash": pdf_hash.hex(),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "verification_id": verification_id,
        "public_key_fingerprint": public_key_fingerprint(keypair.serialize_public()),
    }

    # Build ZIP content
    zip_path = output_dir / f"{pdf_path.stem}_{verification_id[:8]}.zip"
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # original PDF
            zf.write(pdf_path, arcname="original.pdf")
            # signature binary
            zf.writestr("signature.bin", signature)
            # public key PEM (not private!)
            zf.writestr("public_key.pem", keypair.serialize_public())
            # metadata JSON
            zf.writestr("metadata.json", json.dumps(metadata, indent=2))
    except Exception as exc:
        raise CryptoError(f"Failed to create signed package: {exc}") from exc

    # Insert document record into SQLite database
    try:
        from . import db
        db.add_document(
            original_filename=pdf_path.name,
            sha256_hash=pdf_hash.hex(),
            signing_timestamp=metadata["timestamp"],
            verification_id=verification_id,
            public_key_fingerprint=metadata["public_key_fingerprint"],
            verification_status="signed",
        )
    except Exception as exc:
        raise CryptoError(f"Database insertion failed: {exc}") from exc

    return zip_path


def _is_safe_path(base: Path, target: Path) -> bool:
    """Return ``True`` if ``target`` resolves inside ``base``.

    Prevents Zip Slip attacks by ensuring extracted paths stay within the intended
    directory.
    """
    try:
        return base.resolve() in target.resolve().parents or base.resolve() == target.resolve()
    except Exception:
        return False


def extract_signed_package(zip_path: Path, extract_to: Path) -> dict:
    """Safely extract a signed package and return its metadata dictionary.

    Performs validation of member names to avoid directory traversal. After extraction,
    the function returns the parsed ``metadata.json`` content.

    Args:
        zip_path: Path to the signed ZIP file.
        extract_to: Destination directory for extraction.

    Returns:
        Parsed metadata dictionary.

    Raises:
        CryptoError on any validation or I/O problem.
    """
    if not zip_path.is_file():
        raise CryptoError(f"Package not found: {zip_path}")
    extract_to.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                member_path = Path(member.filename)
                # Reject absolute paths or path components that escape the target dir
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise CryptoError(f"Unsafe file path in zip: {member.filename}")
                # Compute final extraction path and ensure it stays within ``extract_to``
                dest_path = extract_to / member_path
                if not _is_safe_path(extract_to, dest_path):
                    raise CryptoError(f"Zip entry would escape extraction directory: {member.filename}")
                # Extract safely
                zf.extract(member, path=extract_to)
            # Load and return metadata
            metadata_path = extract_to / "metadata.json"
            if not metadata_path.is_file():
                raise CryptoError("metadata.json missing from signed package.")
            metadata = json.loads(metadata_path.read_text())
            return metadata
    except zipfile.BadZipFile as exc:
        raise CryptoError(f"Invalid zip file: {exc}") from exc
    except Exception as exc:
        raise CryptoError(f"Failed to extract signed package: {exc}") from exc
