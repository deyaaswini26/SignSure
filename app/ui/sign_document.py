'''Sign Document page for SignSure.

Uses the existing backend:
- app.crypto.generate_rsa_keypair
- app.crypto.RSAKeyPair.serialize_private / serialize_public / public_key_fingerprint
- app.pdf_handler.create_signed_package, hash_pdf
- app.qrcode_utils.generate_qr_code (optional, for download)
- app.db (statistics handled elsewhere)
''' 

from __future__ import annotations

import io
import json
import pathlib
import zipfile

import streamlit as st

from app import crypto, pdf_handler, qrcode_utils

# Directory where signed packages will be stored (runtime artefact)
SIGNED_DIR = pathlib.Path(__file__).resolve().parents[2] / "signed_packages"
SIGNED_DIR.mkdir(parents=True, exist_ok=True)


def _read_metadata_from_zip(zip_path: pathlib.Path) -> dict:
    """Extract and return the metadata.json dict from a signed package."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        with zf.open("metadata.json") as f:
            return json.load(f)


def render() -> None:
    """Render the Sign Document page.

    Workflow:
    1. Upload a PDF.
    2. Enter a password for private‑key encryption.
    3. Generate RSA‑2048 key pair.
    4. Create signed ZIP (backend does DB insertion).
    5. Show hash, fingerprint and provide download buttons.
    """
    st.title("Sign Document")

    uploaded = st.file_uploader("Upload a PDF file", type=["pdf"])
    if not uploaded:
        st.info("Please upload a PDF to begin.")
        return

    password = st.text_input("Password to encrypt the private key", type="password")
    if not password:
        st.warning("Enter a password before signing.")
        return

    # Generate RSA key pair (one per signing operation)
    if st.button("Generate RSA‑2048 key pair & Sign"):
        try:
            keypair = crypto.generate_rsa_keypair()
            # Create signed package – backend will also insert DB record
            # Save uploaded PDF to a temporary file before signing
            temp_pdf_path = SIGNED_DIR / uploaded.name
            with open(temp_pdf_path, "wb") as f:
                f.write(uploaded.getbuffer())
            # Create signed package – backend will also insert DB record
            zip_path = pdf_handler.create_signed_package(
                pdf_path=temp_pdf_path,
                keypair=keypair,
                password=password.encode(),
                output_dir=SIGNED_DIR,
            )
        except Exception as exc:
            st.error(f"Signing failed: {exc}")
            return

        # Load metadata from the created zip
        metadata = _read_metadata_from_zip(zip_path)
        hash_hex = metadata.get("hash", "")
        fingerprint = metadata.get("public_key_fingerprint", "")
        verification_id = metadata.get("verification_id", "")

        st.success("Document signed successfully!")
        st.markdown(f"**SHA‑256 hash:** `{hash_hex}`")
        st.markdown(f"**Public‑key fingerprint:** `{fingerprint}`")
        st.markdown(f"**Verification ID:** `{verification_id}`")

        # Prepare downloadable files
        # 1. Signed ZIP package
        with open(zip_path, "rb") as f:
            zip_bytes = f.read()
        st.download_button(
            label="Download Signed ZIP",
            data=zip_bytes,
            file_name=zip_path.name,
            mime="application/zip",
        )
        # 2. Encrypted private key PEM
        priv_pem = keypair.serialize_private(password.encode())
        st.download_button(
            label="Download Encrypted Private Key (PEM)",
            data=priv_pem,
            file_name="private_key.pem",
            mime="application/octet-stream",
        )
        # 3. Public key PEM
        pub_pem = keypair.serialize_public()
        st.download_button(
            label="Download Public Key (PEM)",
            data=pub_pem,
            file_name="public_key.pem",
            mime="application/octet-stream",
        )
        # 4. QR code for verification ID (optional visual aid)
        qr_path = qrcode_utils.generate_qr_code(verification_id)
        with open(qr_path, "rb") as f:
            qr_bytes = f.read()
        st.download_button(
            label="Download QR code (PNG)",
            data=qr_bytes,
            file_name=qr_path.name,
            mime="image/png",
        )
        st.success("All artefacts are ready for download.")
