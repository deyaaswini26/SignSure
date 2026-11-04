'''Verify Document page for SignSure.

Uses the existing backend:
- app.pdf_handler.extract_signed_package, hash_pdf
- app.crypto.RSAKeyPair.load_public, verify_signature
- app.db.is_signer_trusted, get_document_by_verification_id, record_verification
''' 

from __future__ import annotations

import pathlib
import shutil
import tempfile

import streamlit as st

from app import crypto, pdf_handler, db

# Directory for temporary extraction (cleared each verification)
_TEMP_ROOT = pathlib.Path(__file__).resolve().parents[2] / "temp_extracted"
_TEMP_ROOT.mkdir(parents=True, exist_ok=True)


def _save_uploaded_zip(uploaded) -> pathlib.Path:
    """Save the uploaded Streamlit file to a temporary location and return the Path."""
    temp_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
    with open(temp_path, "wb") as f:
        f.write(uploaded.getbuffer())
    return pathlib.Path(temp_path)


def _display_status(is_valid: bool, is_trusted: bool) -> None:
    """Render the verification outcome with colour coding."""
    if is_valid and is_trusted:
        st.success("✅ VALID & TRUSTED")
    elif is_valid and not is_trusted:
        st.warning("⚠️ VALID BUT UNTRUSTED")
    else:
        st.error("❌ INVALID / TAMPERED")


def render() -> None:
    """Render the Verify Document page.

    Workflow:
    1. Upload a signed ZIP package.
    2. Safely extract it.
    3. Re‑compute the PDF hash and verify the RSA‑PSS signature.
    4. Look up the signer trust status.
    5. Record the verification attempt in the database.
    6. Show result, metadata and provide download links for the original PDF and metadata.
    """
    st.title("Verify Document")

    uploaded = st.file_uploader("Upload a signed ZIP package", type=["zip"])
    if not uploaded:
        st.info("Please upload a signed package to begin verification.")
        return

    # Save uploaded zip to a temporary file
    zip_path = _save_uploaded_zip(uploaded)

    # Create a fresh extraction directory for this run
    extract_dir = _TEMP_ROOT / zip_path.stem
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        metadata = pdf_handler.extract_signed_package(zip_path, extract_dir)
    except Exception as exc:
        st.error(f"Failed to extract package: {exc}")
        return

    # Paths inside the extracted folder
    pdf_path = extract_dir / "original.pdf"
    signature_path = extract_dir / "signature.bin"
    pub_key_path = extract_dir / "public_key.pem"

    # Compute hash of the extracted PDF
    try:
        pdf_hash = pdf_handler.hash_pdf(pdf_path)
    except Exception as exc:
        st.error(f"Failed to hash PDF: {exc}")
        return

    # Load public key and signature
    try:
        public_key = crypto.RSAKeyPair.load_public(pub_key_path.read_bytes())
        signature = signature_path.read_bytes()
    except Exception as exc:
        st.error(f"Failed to load public key or signature: {exc}")
        return

    # Verify signature
    is_valid = crypto.verify_signature(public_key, pdf_hash, signature)

    # Check trust status of the signer
    fingerprint = metadata.get("public_key_fingerprint", "")
    is_trusted = db.is_signer_trusted(fingerprint)

    # Record verification attempt
    try:
        doc_record = db.get_document_by_verification_id(metadata.get("verification_id", ""))
        document_id = doc_record["document_id"] if doc_record else None
        db.record_verification(
            verification_id=metadata.get("verification_id", ""),
            document_id=document_id or -1,
            result=is_valid,
            failure_reason=None if is_valid else "Signature verification failed",
        )
    except Exception as exc:
        st.warning(f"Could not record verification in DB: {exc}")

    # Display outcome
    _display_status(is_valid, is_trusted)

    # Show metadata summary
    st.subheader("Package metadata")
    st.json(metadata)

    # Provide downloads for original PDF and metadata JSON
    if pdf_path.is_file():
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        st.download_button(
            label="Download original PDF",
            data=pdf_bytes,
            file_name="original.pdf",
            mime="application/pdf",
        )
    # Metadata JSON download
    metadata_json = st.json(metadata)  # already displayed; create a download
    st.download_button(
        label="Download metadata JSON",
        data=bytes(str(metadata), "utf-8"),
        file_name="metadata.json",
        mime="application/json",
    )

    # Cleanup temporary files (keep zip for possible re‑download)
    try:
        zip_path.unlink(missing_ok=True)
    except Exception:
        pass

