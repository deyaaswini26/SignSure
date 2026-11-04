"""Overview page (Document Security Console) for SignSure.

Displays:
- Live database telemetry: Documents Signed, Successful Verifications, Failed Verifications, Trusted Signers.
- End-to-end visual representation of the SignSure cryptographic workflow:
  PDF Upload → SHA-256 Hashing → RSA-PSS Signing → Signed Package → Signature Verification → Trust Assessment.
- Compact technical specification of the cryptographic primitives and trust architecture.
- Recent signed documents registry snapshot from SQLite.
"""

from __future__ import annotations

import html
import streamlit as st

from app import db
from app.ui.components import render_page_header, status_badge_html


def render() -> None:
    """Render the Document Security Console overview page."""
    render_page_header(
        eyebrow="MODULE 01 // SECURITY CONSOLE OVERVIEW",
        title="SignSure Document Security Console",
        subtitle="Asymmetric PDF integrity protection, probabilistic signature verification, and public-key trust evaluation.",
        spec_badge="PKCS#1 v2.1 // RSA-PSS // SHA-256",
    )

    # Fetch live database statistics
    try:
        stats = db.get_stats()
    except Exception as exc:
        st.error(f"Database telemetry error: {exc}")
        stats = {
            "total_documents": 0,
            "successful_verifications": 0,
            "failed_verifications": 0,
            "trusted_signers": 0,
        }

    docs_signed = stats.get("total_documents", 0)
    verif_ok = stats.get("successful_verifications", 0)
    verif_fail = stats.get("failed_verifications", 0)
    trusted_cnt = stats.get("trusted_signers", 0)

    # 1. Live Database Telemetry Grid
    st.markdown(
        f"""
        <div class="ss-metric-grid">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Documents Signed</div>
                <div class="ss-metric-value">{docs_signed}</div>
                <div class="ss-metric-sub">Registered in <code>documents</code> table</div>
            </div>
            <div class="ss-metric-card accent-emerald">
                <div class="ss-metric-label">Successful Verifications</div>
                <div class="ss-metric-value">{verif_ok}</div>
                <div class="ss-metric-sub">Cryptographic check passed (<code>result=1</code>)</div>
            </div>
            <div class="ss-metric-card accent-red">
                <div class="ss-metric-label">Failed Verifications</div>
                <div class="ss-metric-value">{verif_fail}</div>
                <div class="ss-metric-sub">Tampered / invalid signature (<code>result=0</code>)</div>
            </div>
            <div class="ss-metric-card accent-indigo">
                <div class="ss-metric-label">Trusted Signers</div>
                <div class="ss-metric-value">{trusted_cnt}</div>
                <div class="ss-metric-sub">Active keys (<code>trust_status='trusted'</code>)</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. End-to-End Security Workflow Pipeline
    st.markdown(
        """
        <div class="ss-panel">
            <div class="ss-panel-header">
                <div class="ss-panel-title">SignSure Cryptographic Architecture &amp; Verification Pipeline</div>
                <span class="ss-panel-tag">END-TO-END WORKFLOW</span>
            </div>
            <div class="ss-pipeline">
                <div class="ss-pipe-step">
                    <div class="ss-pipe-num">STAGE 01 &rarr;</div>
                    <div class="ss-pipe-title">PDF Upload</div>
                    <div class="ss-pipe-desc">Strict <code>.pdf</code> extension &amp; <code>%PDF-</code> magic-byte header validation.</div>
                </div>
                <div class="ss-pipe-step">
                    <div class="ss-pipe-num">STAGE 02 &rarr;</div>
                    <div class="ss-pipe-title">SHA-256 Hashing</div>
                    <div class="ss-pipe-desc">Deterministic 256-bit (32-byte) message digest computed over raw PDF bytes.</div>
                </div>
                <div class="ss-pipe-step">
                    <div class="ss-pipe-num">STAGE 03 &rarr;</div>
                    <div class="ss-pipe-title">RSA-PSS Signing</div>
                    <div class="ss-pipe-desc">2048-bit RSA private key signs digest with PSS padding (MGF1 + SHA-256).</div>
                </div>
                <div class="ss-pipe-step">
                    <div class="ss-pipe-num">STAGE 04 &rarr;</div>
                    <div class="ss-pipe-title">Signed Package</div>
                    <div class="ss-pipe-desc">ZIP container bundling <code>original.pdf</code>, <code>signature.bin</code>, <code>public_key.pem</code>, <code>metadata.json</code>.</div>
                </div>
                <div class="ss-pipe-step">
                    <div class="ss-pipe-num">STAGE 05 &rarr;</div>
                    <div class="ss-pipe-title">Signature Verification</div>
                    <div class="ss-pipe-desc">Zip-Slip safe extraction, PDF hash recomputation &amp; RSA-PSS verification.</div>
                </div>
                <div class="ss-pipe-step">
                    <div class="ss-pipe-num">STAGE 06 &#10003;</div>
                    <div class="ss-pipe-title">Trust Assessment</div>
                    <div class="ss-pipe-desc">SHA-256 public-key fingerprint lookup against the SQLite signer registry.</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Compact Technical Reference (2-column layout)
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown(
            """
            <div class="ss-panel">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Cryptographic Primitives Specification</div>
                    <span class="ss-panel-tag">CORE CRYPTO</span>
                </div>
                <table class="ss-kv-table">
                    <tr>
                        <th>Asymmetric Key Pair</th>
                        <td><span class="ss-mono">RSA-2048</span> (Modulus 2048-bit, public exponent <code>e = 65537</code>)</td>
                    </tr>
                    <tr>
                        <th>Signature Scheme</th>
                        <td><span class="ss-mono">RSA-PSS</span> (Probabilistic Signature Scheme, randomized salt)</td>
                    </tr>
                    <tr>
                        <th>Mask Generation</th>
                        <td><span class="ss-mono">MGF1(SHA-256)</span> with <code>PSS.MAX_LENGTH</code> salt</td>
                    </tr>
                    <tr>
                        <th>Document Digest</th>
                        <td><span class="ss-mono">SHA-256</span> (256-bit / 64-hex-character collision-resistant hash)</td>
                    </tr>
                    <tr>
                        <th>Key Serialization</th>
                        <td>Private: <span class="ss-mono">PKCS#8 PEM</span> &bull; Public: <span class="ss-mono">SubjectPublicKeyInfo PEM</span></td>
                    </tr>
                    <tr>
                        <th>Key Fingerprint</th>
                        <td><span class="ss-mono">SHA-256(public_key.pem)</span> rendered as 64-char hex identifier</td>
                    </tr>
                </table>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_right:
        st.markdown(
            """
            <div class="ss-panel">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Security Guarantees &amp; Trust Separation</div>
                    <span class="ss-panel-tag">SECURITY MODEL</span>
                </div>
                <table class="ss-kv-table">
                    <tr>
                        <th>Document Integrity</th>
                        <td>Any single-bit alteration in <code>original.pdf</code> changes the recalculated SHA-256 digest and invalidates the RSA-PSS signature.</td>
                    </tr>
                    <tr>
                        <th>Authenticity vs. Trust</th>
                        <td>Cryptographic validity proves the package was signed by the holder of the matching private key; it does <strong>not</strong> by itself prove real-world identity.</td>
                    </tr>
                    <tr>
                        <th>Signer Registry Lookup</th>
                        <td>Identity trust is evaluated separately by matching the public-key SHA-256 fingerprint against registered &amp; non-revoked signers.</td>
                    </tr>
                    <tr>
                        <th>Private Key Isolation</th>
                        <td>The private key is <strong>never</strong> bundled inside the signed ZIP archive; only <code>public_key.pem</code> travels with the package.</td>
                    </tr>
                    <tr>
                        <th>QR Lookup Token</th>
                        <td>Generated QR codes store only the UUID <code>verification_id</code> for database lookup and do not independently validate signatures.</td>
                    </tr>
                </table>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 4. Recent Signed Documents Registry Snapshot
    try:
        docs = db.list_documents()
    except Exception:
        docs = []

    st.markdown(
        """
        <div class="ss-panel" style="margin-bottom: 0.25rem;">
            <div class="ss-panel-header" style="margin-bottom: 0.5rem;">
                <div class="ss-panel-title">Recent Signed Documents Registry</div>
                <span class="ss-panel-tag">SQLITE // DOCUMENTS TABLE</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    if not docs:
        st.caption("No signed documents recorded in the database yet. Use **Digital Signing** to sign a PDF document.")
    else:
        rows_html = []
        for d in docs[:8]:
            doc_id = d.get("document_id", "")
            fname = html.escape(str(d.get("original_filename", "")))
            verif_id = html.escape(str(d.get("verification_id", "")))
            sha_short = html.escape(str(d.get("sha256_hash", ""))[:20]) + "…"
            fp_short = html.escape(str(d.get("public_key_fingerprint", ""))[:20]) + "…"
            ts = html.escape(str(d.get("signing_timestamp", "")))
            status_badge = status_badge_html(str(d.get("verification_status", "signed")), "info")
            rows_html.append(
                f"<tr>"
                f"<td><span class='ss-mono'>#{doc_id}</span></td>"
                f"<td><strong>{fname}</strong></td>"
                f"<td><span class='ss-mono'>{verif_id}</span></td>"
                f"<td><span class='ss-mono'>{sha_short}</span></td>"
                f"<td><span class='ss-mono'>{fp_short}</span></td>"
                f"<td>{ts}</td>"
                f"<td>{status_badge}</td>"
                f"</tr>"
            )
        st.markdown(
            f"""
            <div style="overflow-x:auto;">
                <table class="ss-audit-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Document Filename</th>
                            <th>Verification UUID</th>
                            <th>SHA-256 Digest</th>
                            <th>Public-Key Fingerprint</th>
                            <th>Signing Timestamp (UTC)</th>
                            <th>Status</th>
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

