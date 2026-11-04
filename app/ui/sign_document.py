"""Digital Signing page for SignSure.

Presents the signing operation as a structured 5-stage cryptographic workflow:
1. PDF upload and validation (.pdf extension & %PDF- header check)
2. SHA-256 digest generation
3. RSA-2048 key-pair generation
4. RSA-PSS signature creation (MGF1 + SHA-256)
5. Signed ZIP package generation (never includes the private key)

Uses the existing backend:
- app.crypto.generate_rsa_keypair, sha256_digest, public_key_fingerprint
- app.pdf_handler.create_signed_package
- app.qrcode_utils.generate_qr_code
- app.db.register_trusted_signer (optional convenience toggle or info)
"""

from __future__ import annotations

import html
import json
import pathlib
import zipfile

import streamlit as st

from app import crypto, pdf_handler, qrcode_utils
from app.ui.components import render_page_header, render_kv_panel, status_badge_html

# Directory where signed packages will be stored (runtime artefact)
SIGNED_DIR = pathlib.Path(__file__).resolve().parents[2] / "signed_packages"
SIGNED_DIR.mkdir(parents=True, exist_ok=True)


def _read_metadata_from_zip(zip_path: pathlib.Path) -> dict:
    """Extract and return the metadata.json dict from a signed package."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        with zf.open("metadata.json") as f:
            return json.load(f)


def _render_five_stage_tracker(current_stage: int) -> None:
    """Render the 5-stage cryptographic signing workflow tracker.

    current_stage:
      0 = waiting for upload
      1 = PDF uploaded & validated (digest preview ready)
      5 = all 5 stages completed
    """
    stages = [
        ("STAGE 01", "PDF Validation", "Verify .pdf suffix & %PDF- magic header"),
        ("STAGE 02", "SHA-256 Digest", "Compute 256-bit hash over raw PDF bytes"),
        ("STAGE 03", "RSA-2048 KeyGen", "Generate asymmetric key pair (e=65537)"),
        ("STAGE 04", "RSA-PSS Signature", "Sign SHA-256 digest with MGF1(SHA-256)"),
        ("STAGE 05", "ZIP Packaging", "Bundle PDF, signature, pubkey & metadata"),
    ]
    cards = []
    for idx, (num, title, desc) in enumerate(stages, start=1):
        if current_stage >= 5 or (current_stage >= 2 and idx <= 2):
            state_cls = "done"
            badge = "COMPLETED"
        elif idx == current_stage + 1:
            state_cls = "active"
            badge = "READY"
        else:
            state_cls = ""
            badge = "PENDING"
        cards.append(
            f"""
            <div class="ss-pipe-step {state_cls}">
                <div class="ss-pipe-num">{num} // {badge}</div>
                <div class="ss-pipe-title">{html.escape(title)}</div>
                <div class="ss-pipe-desc">{html.escape(desc)}</div>
            </div>
            """
        )

    st.markdown(
        f"""
        <div class="ss-panel">
            <div class="ss-panel-header">
                <div class="ss-panel-title">Structured Cryptographic Signing Workflow</div>
                <span class="ss-panel-tag">5-STAGE PIPELINE</span>
            </div>
            <div style="display:grid; grid-template-columns:repeat(5, 1fr); gap:0.5rem;">
                {''.join(cards)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render() -> None:
    """Render the Digital Signing page."""
    render_page_header(
        eyebrow="MODULE 02 // DIGITAL SIGNING OPERATION",
        title="Cryptographic Document Signing",
        subtitle="Generate a 2048-bit RSA key pair, compute the SHA-256 PDF digest, create an RSA-PSS signature, and package verification artifacts.",
        spec_badge="RSA-2048 // MGF1-SHA256 // PKCS#8",
    )

    col_input, col_precheck = st.columns([1.15, 1])

    with col_input:
        st.markdown(
            """
            <div class="ss-panel" style="margin-bottom:0.65rem;">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Stage 1 &amp; 3 Inputs: Source PDF &amp; Private-Key Passphrase</div>
                    <span class="ss-panel-tag">INPUT PARAMETERS</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        uploaded = st.file_uploader("Select PDF Document (.pdf)", type=["pdf"])
        password = st.text_input(
            "Private-Key Passphrase (required for private key serialization)",
            type="password",
            help="Used when serializing the generated RSA-2048 private key PEM. Never stored in the database or ZIP package.",
        )
        sign_clicked = st.button(
            "Execute Cryptographic Signing Workflow (Stages 1–5)",
            type="primary",
            use_container_width=True,
            disabled=(not uploaded or not password),
        )
        if not uploaded:
            st.caption("Upload a valid `.pdf` file and enter a non-empty passphrase to enable signing.")
        elif not password:
            st.caption("Enter a passphrase before executing the signing workflow.")
        st.markdown("</div>", unsafe_allow_html=True)

    # Pre-check Stage 1 & Stage 2 when a file is uploaded
    pdf_bytes = bytes(uploaded.getbuffer()) if uploaded else None
    header_valid = bool(pdf_bytes and pdf_bytes[:5].startswith(b"%PDF-"))
    pre_hash_hex = crypto.sha256_digest(pdf_bytes).hex() if (pdf_bytes and header_valid) else None

    with col_precheck:
        if not uploaded:
            render_kv_panel(
                title="Stage 1 & 2 Pre-Execution Telemetry",
                tag="AWAITING FILE",
                rows=[
                    ("Document Status", status_badge_html("NO PDF UPLOADED", "neutral"), False),
                    ("Header Check", "%PDF- magic byte verification pending", False),
                    ("SHA-256 Digest", "Pending document byte stream", False),
                    ("Private Key Policy", "Generated per signing event; excluded from ZIP package", False),
                ],
            )
        else:
            hdr_badge = (
                status_badge_html("VALID (%PDF- HEADER VERIFIED)", "pass")
                if header_valid
                else status_badge_html("INVALID HEADER", "fail")
            )
            render_kv_panel(
                title="Stage 1 & 2 Pre-Execution Telemetry",
                tag="PRE-CHECK",
                rows=[
                    ("Document Name", uploaded.name, True),
                    ("Payload Size", f"{len(pdf_bytes):,} bytes", True),
                    ("Stage 1: PDF Validation", hdr_badge, False),
                    ("Stage 2: SHA-256 Digest", pre_hash_hex or "N/A (invalid PDF header)", True),
                ],
            )

    # Execute full signing workflow when button clicked
    if sign_clicked and uploaded and password:
        try:
            # Stage 3: Generate RSA-2048 key pair
            keypair = crypto.generate_rsa_keypair()

            # Save uploaded PDF to signed_packages before calling backend create_signed_package
            temp_pdf_path = SIGNED_DIR / uploaded.name
            with open(temp_pdf_path, "wb") as f:
                f.write(uploaded.getbuffer())

            # Stages 1, 2, 4, 5: Validate PDF, hash, sign with RSA-PSS, create ZIP & record in DB
            zip_path = pdf_handler.create_signed_package(
                pdf_path=temp_pdf_path,
                keypair=keypair,
                password=password.encode(),
                output_dir=SIGNED_DIR,
            )

            metadata = _read_metadata_from_zip(zip_path)
            verification_id = metadata.get("verification_id", "")
            qr_path = qrcode_utils.generate_qr_code(verification_id)

            with open(zip_path, "rb") as f:
                zip_bytes = f.read()
            with open(qr_path, "rb") as f:
                qr_bytes = f.read()

            priv_pem = keypair.serialize_private(password.encode())
            pub_pem = keypair.serialize_public()

            # Read signature length from zip for technical telemetry
            with zipfile.ZipFile(zip_path, "r") as zf:
                sig_len = len(zf.read("signature.bin"))
                zip_members = zf.namelist()

            st.session_state["last_signed_result"] = {
                "filename": metadata.get("filename", uploaded.name),
                "hash_hex": metadata.get("hash", ""),
                "fingerprint": metadata.get("public_key_fingerprint", ""),
                "verification_id": verification_id,
                "timestamp": metadata.get("timestamp", ""),
                "zip_name": zip_path.name,
                "zip_bytes": zip_bytes,
                "priv_pem": priv_pem,
                "pub_pem": pub_pem,
                "qr_name": qr_path.name,
                "qr_bytes": qr_bytes,
                "sig_len": sig_len,
                "zip_members": zip_members,
            }
        except Exception as exc:
            st.error(f"Signing workflow failed: {exc}")
            return

    # Determine tracker stage
    has_result = (
        "last_signed_result" in st.session_state
        and uploaded is not None
        and st.session_state["last_signed_result"].get("filename") == uploaded.name
    )
    if has_result:
        _render_five_stage_tracker(5)
    elif uploaded and header_valid:
        _render_five_stage_tracker(2)
    else:
        _render_five_stage_tracker(0)

    # Display signed output panels if available
    if "last_signed_result" in st.session_state:
        res = st.session_state["last_signed_result"]
        st.markdown(
            f"""
            <div class="ss-verdict-banner ss-verdict-valid-trusted" style="padding:0.75rem 1.1rem;">
                <div>
                    <div class="ss-verdict-label">CRYPTOGRAPHIC SIGNING STATUS // STAGES 1–5 COMPLETE</div>
                    <div class="ss-verdict-title" style="font-size:1.1rem;">SIGNED PACKAGE GENERATED &amp; LOGGED TO DATABASE</div>
                    <p class="ss-verdict-reason">
                        Document <code>{html.escape(res['filename'])}</code> hashed with SHA-256 and signed via RSA-2048 / RSA-PSS (MGF1-SHA256).
                    </p>
                </div>
                <div>{status_badge_html("SIGNATURE CREATED", "pass")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_tech1, col_tech2 = st.columns(2)
        with col_tech1:
            render_kv_panel(
                title="Cryptographic Signature Telemetry",
                tag="STAGES 2–4 OUTPUT",
                badge_html=status_badge_html("RSA-PSS SIGNED", "pass"),
                rows=[
                    ("Document Name", res["filename"], True),
                    ("SHA-256 Digest (Hex)", res["hash_hex"], True),
                    ("Public-Key Fingerprint", res["fingerprint"], True),
                    ("Signature Status", status_badge_html("ACTIVE // 256-BYTE RSA-PSS", "pass"), False),
                    ("Signature Parameters", f"RSA-2048 / PSS / MGF1(SHA-256) / {res['sig_len']} bytes", True),
                ],
            )

        with col_tech2:
            render_kv_panel(
                title="Signed Package Manifest & Security Isolation",
                tag="STAGE 5 OUTPUT",
                badge_html=status_badge_html("PRIVATE KEY EXCLUDED", "info"),
                rows=[
                    ("Package Archive", res["zip_name"], True),
                    ("Verification UUID", res["verification_id"], True),
                    ("Signing Timestamp (UTC)", res["timestamp"], True),
                    ("Archive Contents", ", ".join(res["zip_members"]), True),
                    ("Key Isolation Policy", "Private key is NEVER stored in the ZIP archive or database", False),
                ],
            )

        # Download Panel
        st.markdown(
            """
            <div class="ss-panel">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Cryptographic Artifacts &amp; Detached Key Exports</div>
                    <span class="ss-panel-tag">ARTIFACT DOWNLOADS</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        dcol1, dcol2, dcol3, dcol4 = st.columns(4)
        with dcol1:
            st.download_button(
                label="Download Signed Package (.zip)",
                data=res["zip_bytes"],
                file_name=res["zip_name"],
                mime="application/zip",
                type="primary",
                use_container_width=True,
            )
            st.caption("Contains `original.pdf`, `signature.bin`, `public_key.pem`, `metadata.json`.")
        with dcol2:
            st.download_button(
                label="Download Private Key (.pem)",
                data=res["priv_pem"],
                file_name="private_key.pem",
                mime="application/octet-stream",
                use_container_width=True,
            )
            st.caption("Separately downloadable private key PEM. Keep confidential; never inside ZIP.")
        with dcol3:
            st.download_button(
                label="Download Public Key (.pem)",
                data=res["pub_pem"],
                file_name="public_key.pem",
                mime="application/octet-stream",
                use_container_width=True,
            )
            st.caption("Upload this PEM on the **Trusted Signers** page to register signer trust.")
        with dcol4:
            st.download_button(
                label="Download Lookup QR (.png)",
                data=res["qr_bytes"],
                file_name=res["qr_name"],
                mime="image/png",
                use_container_width=True,
            )
            st.caption("Encodes only the UUID `verification_id` for database record lookup.")
        st.markdown("</div>", unsafe_allow_html=True)
