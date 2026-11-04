"""Trusted Signers page (Security Trust-Management Interface) for SignSure.

Displays and manages the ``trusted_signers`` table:
- Signer name
- Public-key fingerprint (SHA-256 hex of PEM)
- Registration status & timestamp
- Revocation status (active 'trusted' vs 'revoked')
- Registration of new PEM public keys via ``db.register_trusted_signer``
- Revocation of active signers via ``db.revoke_trusted_signer``
"""

from __future__ import annotations

import html
import sqlite3
import streamlit as st

from app import crypto, db
from app.ui.components import render_page_header, render_kv_panel, status_badge_html


def render() -> None:
    """Render the Trusted Signers registry management page."""
    render_page_header(
        eyebrow="MODULE 04 // PUBLIC-KEY TRUST MANAGEMENT",
        title="Trusted Signers Registry & Revocation Console",
        subtitle="Manage trusted RSA public keys, inspect SHA-256 public-key fingerprints, and enforce signer key revocation.",
        spec_badge="SHA-256 FINGERPRINT // TRUST REGISTRY",
    )

    # Fetch all signers from SQLite
    try:
        signers = db.list_trusted_signers()
    except Exception as exc:
        st.error(f"Failed to query trusted_signers table: {exc}")
        signers = []

    active_count = sum(1 for s in signers if s.get("trust_status") == "trusted")
    revoked_count = sum(1 for s in signers if s.get("trust_status") == "revoked")

    # Top summary metrics
    st.markdown(
        f"""
        <div class="ss-metric-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Total Registered Keys</div>
                <div class="ss-metric-value">{len(signers)}</div>
                <div class="ss-metric-sub">Records in <code>trusted_signers</code></div>
            </div>
            <div class="ss-metric-card accent-emerald">
                <div class="ss-metric-label">Active Trusted Signers</div>
                <div class="ss-metric-value">{active_count}</div>
                <div class="ss-metric-sub"><code>trust_status = 'trusted'</code></div>
            </div>
            <div class="ss-metric-card accent-red">
                <div class="ss-metric-label">Revoked Signers</div>
                <div class="ss-metric-value">{revoked_count}</div>
                <div class="ss-metric-sub"><code>trust_status = 'revoked'</code></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_reg, col_revoke = st.columns([1.25, 1])

    # 1. Register a Trusted Signer
    with col_reg:
        st.markdown(
            """
            <div class="ss-panel">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Register Trusted Signer Public Key</div>
                    <span class="ss-panel-tag">REGISTER KEY</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        signer_name = st.text_input(
            "Signer Identity / Organization Name",
            placeholder="e.g., Academic Registrar Office — Key 2026",
        )
        uploaded_pem = st.file_uploader(
            "Upload Public Key PEM (public_key.pem)",
            type=["pem", "pub", "txt"],
            key="trusted_signer_pem_upload",
        )

        pem_bytes = bytes(uploaded_pem.getbuffer()) if uploaded_pem else None
        preview_fp = None
        key_valid = False
        key_info_str = ""

        if pem_bytes:
            try:
                loaded_pub = crypto.RSAKeyPair.load_public(pem_bytes)
                preview_fp = crypto.public_key_fingerprint(pem_bytes)
                key_valid = True
                key_info_str = f"RSA-{loaded_pub.key_size} (e = {loaded_pub.public_numbers().e})"
            except Exception as exc:
                st.error(f"Invalid PEM public key: {exc}")

        if key_valid and preview_fp:
            st.markdown(
                f"""
                <div style="background:#F8FAFC; border:1px solid #CBD5E1; border-radius:4px; padding:0.5rem 0.7rem; margin-bottom:0.65rem; font-size:0.78rem;">
                    <div><strong>Parsed Key Parameters:</strong> <span class="ss-mono">{html.escape(key_info_str)}</span></div>
                    <div style="margin-top:0.25rem;"><strong>Computed SHA-256 Fingerprint:</strong><br><span class="ss-mono">{html.escape(preview_fp)}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        reg_clicked = st.button(
            "Register Public Key as Trusted Signer",
            type="primary",
            use_container_width=True,
            disabled=(not signer_name.strip() or not key_valid),
        )
        if reg_clicked and signer_name.strip() and pem_bytes and key_valid:
            try:
                new_id = db.register_trusted_signer(
                    signer_name=signer_name.strip(),
                    public_key_pem=pem_bytes,
                    trust_status="trusted",
                )
                st.success(f"Signer '{signer_name.strip()}' registered with ID #{new_id}.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("This public-key fingerprint is already registered in the trusted_signers table.")
            except Exception as exc:
                st.error(f"Failed to register trusted signer: {exc}")

        st.markdown("</div>", unsafe_allow_html=True)

    # 2. Revocation Control Panel
    with col_revoke:
        st.markdown(
            """
            <div class="ss-panel">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Signer Key Revocation Control</div>
                    <span class="ss-panel-tag">REVOKE ACCESS</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        active_signers = [s for s in signers if s.get("trust_status") == "trusted"]
        if not active_signers:
            st.caption("No active (`trusted`) signers available to revoke.")
        else:
            options = {
                f"#{s['signer_id']} — {s['signer_name']} ({s['public_key_fingerprint'][:16]}…)": s
                for s in active_signers
            }
            selected_label = st.selectbox(
                "Select Active Signer to Revoke",
                options=list(options.keys()),
            )
            selected_signer = options[selected_label]
            st.markdown(
                f"""
                <div style="background:#FEF2F2; border:1px solid #FCA5A5; border-radius:4px; padding:0.5rem 0.7rem; margin-bottom:0.65rem; font-size:0.78rem; color:#7F1D1D;">
                    Revoking <strong>{html.escape(selected_signer['signer_name'])}</strong> sets <code>trust_status = 'revoked'</code>.
                    Future verifications of packages signed by this key will evaluate to <strong>VALID BUT UNTRUSTED</strong>.
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("Revoke Selected Signer Key", use_container_width=True):
                try:
                    db.revoke_trusted_signer(int(selected_signer["signer_id"]))
                    st.warning(f"Signer #{selected_signer['signer_id']} ({selected_signer['signer_name']}) has been revoked.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Revocation failed: {exc}")

        st.markdown("</div>", unsafe_allow_html=True)

    # 3. Trusted Signers Registry Table
    st.markdown(
        """
        <div class="ss-panel">
            <div class="ss-panel-header">
                <div class="ss-panel-title">Trusted Signers Registry Directory</div>
                <span class="ss-panel-tag">SQLITE // TRUSTED_SIGNERS</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    if not signers:
        st.caption("No signers are currently registered in the database.")
    else:
        rows_html = []
        for s in signers:
            sid = s.get("signer_id", "")
            sname = html.escape(str(s.get("signer_name", "")))
            fp = html.escape(str(s.get("public_key_fingerprint", "")))
            reg_ts = html.escape(str(s.get("registration_timestamp", "")))
            t_status = str(s.get("trust_status", ""))

            reg_badge = status_badge_html("REGISTERED", "info")
            if t_status == "trusted":
                rev_badge = status_badge_html("ACTIVE (NOT REVOKED)", "pass")
            else:
                rev_badge = status_badge_html("REVOKED", "fail")

            rows_html.append(
                f"<tr>"
                f"<td><span class='ss-mono'>#{sid}</span></td>"
                f"<td><strong>{sname}</strong></td>"
                f"<td><span class='ss-mono'>{fp}</span></td>"
                f"<td>{reg_ts}</td>"
                f"<td>{reg_badge}</td>"
                f"<td>{rev_badge}</td>"
                f"</tr>"
            )

        st.markdown(
            f"""
            <div style="overflow-x:auto;">
                <table class="ss-audit-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Signer Name</th>
                            <th>Public-Key SHA-256 Fingerprint</th>
                            <th>Registration Timestamp (UTC)</th>
                            <th>Registration Status</th>
                            <th>Revocation / Trust Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

