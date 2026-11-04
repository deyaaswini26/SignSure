"""Signature Verification page for SignSure.

Evaluates and clearly displays three distinct cryptographic and trust checks:
A. Document Integrity:
   - Recalculated SHA-256 hash
   - Stored SHA-256 hash (metadata & database record)
   - Hash comparison result
B. Signature Authenticity:
   - RSA-PSS verification result
   - Public key used for verification
   - Signature validity
C. Signer Trust:
   - Public-key fingerprint
   - Trusted registry lookup
   - Active / revoked / unregistered status

Prominent final verdict:
- VALID & TRUSTED
- VALID BUT UNTRUSTED
- INVALID / TAMPERED

Uses the existing backend:
- app.pdf_handler.extract_signed_package, hash_pdf
- app.crypto.RSAKeyPair.load_public, verify_signature, public_key_fingerprint
- app.db.is_signer_trusted, get_signer_record_by_fingerprint, get_document_by_verification_id, record_verification
"""

from __future__ import annotations

import html
import json
import pathlib
import shutil
import tempfile
from typing import List, Optional

import streamlit as st

from app import crypto, pdf_handler, db
from app.ui.components import render_page_header, render_kv_panel, status_badge_html

# Directory for temporary extraction (cleared each verification)
_TEMP_ROOT = pathlib.Path(__file__).resolve().parents[2] / "temp_extracted"
_TEMP_ROOT.mkdir(parents=True, exist_ok=True)


def _save_uploaded_zip(uploaded) -> pathlib.Path:
    """Save the uploaded Streamlit file to a temporary location and return the Path."""
    temp_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
    with open(temp_path, "wb") as f:
        f.write(uploaded.getbuffer())
    return pathlib.Path(temp_path)


def _render_verdict_banner(
    is_crypto_valid: bool,
    is_trusted: bool,
    trust_state_label: str,
    failure_reasons: List[str],
) -> None:
    """Render the prominent final verification verdict banner and diagnostic summary."""
    if is_crypto_valid and is_trusted:
        cls = "ss-verdict-valid-trusted"
        title = "VALID & TRUSTED"
        badge = status_badge_html("ALL CHECKS PASSED", "pass")
        explanation = (
            "Check A (Document Integrity) and Check B (RSA-PSS Signature Authenticity) succeeded, "
            "and Check C confirmed the signer's public-key fingerprint is registered and active in the Trusted Signers Registry."
        )
    elif is_crypto_valid and not is_trusted:
        cls = "ss-verdict-valid-untrusted"
        title = "VALID BUT UNTRUSTED"
        badge = status_badge_html(f"UNTRUSTED ({trust_state_label})", "warn")
        explanation = (
            "Check A (Document Integrity) and Check B (RSA-PSS Signature Authenticity) succeeded — "
            "the PDF has NOT been modified since signing and the signature mathematically matches the bundled public key. "
            f"However, Check C (Signer Trust) determined the signer key is {trust_state_label} in the local trust registry."
        )
    else:
        cls = "ss-verdict-invalid"
        title = "INVALID / TAMPERED"
        badge = status_badge_html("VERIFICATION FAILED", "fail")
        explanation = " // ".join(failure_reasons) if failure_reasons else (
            "Cryptographic verification failed due to document modification or signature mismatch."
        )

    st.markdown(
        f"""
        <div class="ss-verdict-banner {cls}">
            <div style="padding-right: 1rem;">
                <div class="ss-verdict-label">FINAL CRYPTOGRAPHIC &amp; TRUST VERDICT</div>
                <div class="ss-verdict-title">{html.escape(title)}</div>
                <p class="ss-verdict-reason">{html.escape(explanation)}</p>
            </div>
            <div>{badge}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render() -> None:
    """Render the Signature Verification page."""
    render_page_header(
        eyebrow="MODULE 03 // CRYPTOGRAPHIC VERIFICATION & TRUST EVALUATION",
        title="Three-Stage Signature & Trust Verification",
        subtitle="Independently evaluate (A) SHA-256 Document Integrity, (B) RSA-PSS Signature Authenticity, and (C) Signer Registry Trust.",
        spec_badge="SHA-256 // RSA-PSS // TRUST REGISTRY",
    )

    st.markdown(
        """
        <div class="ss-panel" style="margin-bottom: 0.9rem;">
            <div class="ss-panel-header">
                <div class="ss-panel-title">Signed Package Input (.zip)</div>
                <span class="ss-panel-tag">ZIP-SLIP PROTECTED EXTRACTION</span>
            </div>
        """,
        unsafe_allow_html=True,
    )
    uploaded = st.file_uploader(
        "Upload a signed ZIP package containing original.pdf, signature.bin, public_key.pem, and metadata.json",
        type=["zip"],
    )
    st.markdown("</div>", unsafe_allow_html=True)

    if not uploaded:
        # Show empty structural preview of the 3 checks so the user sees the evaluation architecture immediately
        c1, c2, c3 = st.columns(3)
        with c1:
            render_kv_panel(
                title="Check A: Document Integrity",
                tag="SHA-256",
                badge_html=status_badge_html("AWAITING PACKAGE", "neutral"),
                rows=[
                    ("Recalculated SHA-256", "Pending original.pdf extraction", False),
                    ("Stored SHA-256", "Pending metadata.json parse", False),
                    ("Hash Comparison", "Awaiting input", False),
                ],
            )
        with c2:
            render_kv_panel(
                title="Check B: Signature Authenticity",
                tag="RSA-PSS",
                badge_html=status_badge_html("AWAITING PACKAGE", "neutral"),
                rows=[
                    ("RSA-PSS Verification", "Pending signature.bin & digest", False),
                    ("Public Key Used", "Pending public_key.pem load", False),
                    ("Signature Validity", "Awaiting input", False),
                ],
            )
        with c3:
            render_kv_panel(
                title="Check C: Signer Trust",
                tag="REGISTRY",
                badge_html=status_badge_html("AWAITING PACKAGE", "neutral"),
                rows=[
                    ("Public-Key Fingerprint", "Pending SHA-256(public_key.pem)", False),
                    ("Registry Lookup", "Pending SQLite query", False),
                    ("Signer Trust Status", "Awaiting input", False),
                ],
            )
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
        st.markdown(
            f"""
            <div class="ss-verdict-banner ss-verdict-invalid">
                <div>
                    <div class="ss-verdict-label">PACKAGE EXTRACTION ERROR</div>
                    <div class="ss-verdict-title">INVALID / CORRUPTED PACKAGE</div>
                    <p class="ss-verdict-reason">{html.escape(str(exc))}</p>
                </div>
                <div>{status_badge_html("EXTRACTION FAILED", "fail")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        zip_path.unlink(missing_ok=True)
        return

    # Paths inside the extracted folder
    pdf_path = extract_dir / "original.pdf"
    signature_path = extract_dir / "signature.bin"
    pub_key_path = extract_dir / "public_key.pem"

    # Compute hash of the extracted PDF
    try:
        pdf_hash = pdf_handler.hash_pdf(pdf_path)
        recalculated_hash_hex = pdf_hash.hex()
    except Exception as exc:
        st.error(f"Failed to hash extracted PDF: {exc}")
        zip_path.unlink(missing_ok=True)
        return

    # Load public key and signature
    try:
        pub_key_bytes = pub_key_path.read_bytes()
        public_key = crypto.RSAKeyPair.load_public(pub_key_bytes)
        signature = signature_path.read_bytes()
    except Exception as exc:
        st.error(f"Failed to load public key or signature from package: {exc}")
        zip_path.unlink(missing_ok=True)
        return

    # Lookup document record in SQLite if present
    verification_id = metadata.get("verification_id", "")
    doc_record = db.get_document_by_verification_id(verification_id)

    # --- CHECK A: DOCUMENT INTEGRITY ---
    stored_hash_hex = str(metadata.get("hash", "")).strip()
    db_hash_hex: Optional[str] = doc_record.get("sha256_hash") if doc_record else None

    hash_matches_metadata = (recalculated_hash_hex.lower() == stored_hash_hex.lower()) and bool(stored_hash_hex)
    hash_matches_db = (db_hash_hex is None) or (recalculated_hash_hex.lower() == db_hash_hex.lower())
    check_a_passed = hash_matches_metadata and hash_matches_db

    # --- CHECK B: SIGNATURE AUTHENTICITY ---
    # Verify RSA-PSS signature against recalculated PDF hash
    rsa_pss_valid = crypto.verify_signature(public_key, pdf_hash, signature)
    computed_pub_fp = crypto.public_key_fingerprint(pub_key_bytes)
    metadata_pub_fp = str(metadata.get("public_key_fingerprint", "")).strip()
    pub_fp_consistent = (not metadata_pub_fp) or (computed_pub_fp.lower() == metadata_pub_fp.lower())

    # Overall cryptographic validity requires both Check A (hash integrity) and Check B (RSA-PSS valid)
    is_crypto_valid = check_a_passed and rsa_pss_valid and pub_fp_consistent

    # Extract RSA public key parameters for technical display
    pub_numbers = public_key.public_numbers()
    key_size_bits = public_key.key_size
    pub_exponent = pub_numbers.e

    # --- CHECK C: SIGNER TRUST ---
    fingerprint = computed_pub_fp
    is_trusted = db.is_signer_trusted(fingerprint)
    signer_record = db.get_signer_record_by_fingerprint(fingerprint)

    if signer_record is None:
        trust_state_label = "UNREGISTERED"
        trust_badge = status_badge_html("UNREGISTERED SIGNER", "warn")
        registry_lookup_desc = "No matching public-key fingerprint in trusted_signers table"
        signer_name_display = "Unknown / Unregistered Signer"
    elif signer_record.get("trust_status") == "revoked":
        trust_state_label = "REVOKED"
        trust_badge = status_badge_html("REVOKED SIGNER", "fail")
        registry_lookup_desc = f"Record #{signer_record.get('signer_id')} found — status is REVOKED"
        signer_name_display = f"{signer_record.get('signer_name')} (Revoked)"
    else:
        trust_state_label = "ACTIVE / TRUSTED"
        trust_badge = status_badge_html("ACTIVE & TRUSTED", "pass")
        registry_lookup_desc = f"Record #{signer_record.get('signer_id')} matched — registered {signer_record.get('registration_timestamp')}"
        signer_name_display = str(signer_record.get("signer_name"))

    # Diagnose exact failure reasons when verification fails
    failure_reasons: List[str] = []
    if not hash_matches_metadata:
        failure_reasons.append(
            "Check A Failed (Document Integrity): Recalculated PDF SHA-256 digest does not match the stored hash in metadata.json."
        )
    elif not hash_matches_db:
        failure_reasons.append(
            "Check A Failed (Document Integrity): Recalculated PDF SHA-256 digest does not match the original database record."
        )
    if not rsa_pss_valid:
        failure_reasons.append(
            "Check B Failed (Signature Authenticity): RSA-PSS cryptographic verification failed against original.pdf digest."
        )
    if not pub_fp_consistent:
        failure_reasons.append(
            "Check B Failed (Key Mismatch): Bundled public_key.pem fingerprint does not match metadata fingerprint."
        )

    db_failure_reason = "; ".join(failure_reasons) if not is_crypto_valid else None

    # Record verification attempt in database (deduplicate across Streamlit re-runs for the exact same upload interaction)
    dedup_token = f"{uploaded.name}:{len(uploaded.getbuffer())}:{recalculated_hash_hex}:{is_crypto_valid}:{trust_state_label}"
    if st.session_state.get("last_logged_verification_token") != dedup_token:
        try:
            document_id = doc_record["document_id"] if doc_record else None
            db.record_verification(
                verification_id=verification_id,
                document_id=document_id or -1,
                result=is_crypto_valid,
                failure_reason=db_failure_reason,
            )
            st.session_state["last_logged_verification_token"] = dedup_token
        except Exception as exc:
            st.warning(f"Could not record verification in DB: {exc}")

    # 1. Prominent Final Verdict Banner
    _render_verdict_banner(
        is_crypto_valid=is_crypto_valid,
        is_trusted=is_trusted,
        trust_state_label=trust_state_label,
        failure_reasons=failure_reasons,
    )

    # 2. Three Distinct Verification Checks (A, B, C)
    render_kv_panel(
        title="Check A — Document Integrity Verification (SHA-256 Digest Comparison)",
        tag="CHECK A // INTEGRITY",
        badge_html=status_badge_html(
            "INTEGRITY VERIFIED (HASH MATCH)" if check_a_passed else "INTEGRITY FAILURE (HASH MISMATCH)",
            "pass" if check_a_passed else "fail",
        ),
        rows=[
            ("Recalculated SHA-256 Hash", recalculated_hash_hex, True),
            ("Stored SHA-256 Hash (Package)", stored_hash_hex or "MISSING", True),
            (
                "Origin Database SHA-256 Hash",
                db_hash_hex if db_hash_hex else "Not found in local documents table (external package)",
                True if db_hash_hex else False,
            ),
            (
                "Hash Comparison Result",
                status_badge_html("EXACT 256-BIT DIGEST MATCH", "pass")
                if check_a_passed
                else status_badge_html("DIGEST MISMATCH — DOCUMENT MODIFIED", "fail"),
                False,
            ),
        ],
    )

    col_b, col_c = st.columns(2)

    with col_b:
        pub_pem_lines = pub_key_bytes.decode("utf-8", errors="replace").strip().splitlines()
        pub_pem_preview = (
            f"{pub_pem_lines[0]} ... {pub_pem_lines[1][:28]}... ({len(pub_key_bytes)} bytes)"
            if len(pub_pem_lines) >= 2
            else f"{len(pub_key_bytes)} bytes PEM"
        )
        render_kv_panel(
            title="Check B — Signature Authenticity (RSA-PSS)",
            tag="CHECK B // AUTHENTICITY",
            badge_html=status_badge_html(
                "SIGNATURE VALID" if (rsa_pss_valid and pub_fp_consistent) else "SIGNATURE INVALID",
                "pass" if (rsa_pss_valid and pub_fp_consistent) else "fail",
            ),
            rows=[
                (
                    "RSA-PSS Verification Result",
                    status_badge_html("VERIFIED (MGF1-SHA256)", "pass")
                    if rsa_pss_valid
                    else status_badge_html("MATHEMATICAL VERIFICATION FAILED", "fail"),
                    False,
                ),
                ("Public Key Used", f"RSA-{key_size_bits} (e = {pub_exponent})", True),
                ("Bundled Public Key PEM", pub_pem_preview, True),
                ("Signature Payload Size", f"{len(signature)} bytes (signature.bin)", True),
                (
                    "Cryptographic Signature Validity",
                    status_badge_html("AUTHENTIC SIGNATURE", "pass")
                    if (rsa_pss_valid and pub_fp_consistent)
                    else status_badge_html("INVALID / TAMPERED", "fail"),
                    False,
                ),
            ],
        )

    with col_c:
        render_kv_panel(
            title="Check C — Signer Trust Assessment (Registry)",
            tag="CHECK C // TRUST",
            badge_html=trust_badge,
            rows=[
                ("Public-Key Fingerprint", fingerprint, True),
                ("Trusted Registry Lookup", registry_lookup_desc, False),
                ("Registered Signer Name", signer_name_display, False),
                ("Registry Trust Status", trust_badge, False),
                (
                    "Security Separation Note",
                    "Signer trust is independent of RSA-PSS mathematical signature validity.",
                    False,
                ),
            ],
        )

    # 3. Package Metadata & Artifact Inspection / Downloads
    col_meta, col_dl = st.columns([1.3, 1])
    with col_meta:
        render_kv_panel(
            title="Extracted Package Metadata (metadata.json)",
            tag="PACKAGE MANIFEST",
            rows=[
                ("Original Filename", str(metadata.get("filename", "")), True),
                ("Verification ID (UUID)", verification_id, True),
                ("Signing Timestamp (UTC)", str(metadata.get("timestamp", "")), True),
            ],
        )

    with col_dl:
        st.markdown(
            """
            <div class="ss-panel">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Extracted Artifacts &amp; Key Export</div>
                    <span class="ss-panel-tag">EXTRACTED FILES</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        b1, b2, b3 = st.columns(3)
        with b1:
            if pdf_path.is_file():
                st.download_button(
                    label="Original PDF",
                    data=pdf_path.read_bytes(),
                    file_name=metadata.get("filename", "original.pdf"),
                    mime="application/pdf",
                    use_container_width=True,
                )
        with b2:
            st.download_button(
                label="Metadata JSON",
                data=json.dumps(metadata, indent=2).encode("utf-8"),
                file_name="metadata.json",
                mime="application/json",
                use_container_width=True,
            )
        with b3:
            st.download_button(
                label="Bundled Public Key",
                data=pub_key_bytes,
                file_name="public_key.pem",
                mime="application/octet-stream",
                use_container_width=True,
            )
        st.caption(
            "Tip: If Check B is valid but Check C shows **UNREGISTERED**, you can export the **Bundled Public Key** "
            "and register it on the **Trusted Signers** page after out-of-band identity verification."
        )
        st.markdown("</div>", unsafe_allow_html=True)

    # Cleanup temporary zip file
    try:
        zip_path.unlink(missing_ok=True)
    except Exception:
        pass
