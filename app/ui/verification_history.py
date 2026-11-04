"""Verification History (Audit Log) page for SignSure.

Displays a compact security audit-log table from ``verification_logs`` joined with ``documents`` and ``trusted_signers``:
- Document identifier (Document ID, filename, and Verification UUID)
- Timestamp (UTC)
- Verification result (PASS / FAIL)
- Signer information (Registered signer name, trust status, public-key fingerprint)
- Relevant verification details (SHA-256 hash, failure reason if failed)
- Also supports UUID lookup via ``qrcode_utils.lookup_verification`` for QR-encoded verification IDs.
"""

from __future__ import annotations

import html
import streamlit as st

from app import db, qrcode_utils
from app.ui.components import render_page_header, render_kv_panel, status_badge_html


def render() -> None:
    """Render the Verification History audit log page."""
    render_page_header(
        eyebrow="MODULE 05 // SECURITY AUDIT TRAIL & VERIFICATION LOGS",
        title="Verification Audit Log & Document Lookup",
        subtitle="Immutable record of cryptographic verification events, signer trust correlations, and failure diagnostics.",
        spec_badge="SQLITE // VERIFICATION_LOGS",
    )

    try:
        logs = db.list_all_verification_logs()
    except Exception as exc:
        st.error(f"Failed to load verification logs: {exc}")
        logs = []

    total_logs = len(logs)
    passed_logs = sum(1 for r in logs if r.get("verification_result") == 1)
    failed_logs = sum(1 for r in logs if r.get("verification_result") == 0)

    # Top Audit Summary Metrics
    st.markdown(
        f"""
        <div class="ss-metric-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="ss-metric-card">
                <div class="ss-metric-label">Total Audit Events</div>
                <div class="ss-metric-value">{total_logs}</div>
                <div class="ss-metric-sub">Recorded in <code>verification_logs</code></div>
            </div>
            <div class="ss-metric-card accent-emerald">
                <div class="ss-metric-label">Successful Verifications</div>
                <div class="ss-metric-value">{passed_logs}</div>
                <div class="ss-metric-sub">Cryptographic check passed (<code>result = 1</code>)</div>
            </div>
            <div class="ss-metric-card accent-red">
                <div class="ss-metric-label">Failed / Tampered Events</div>
                <div class="ss-metric-value">{failed_logs}</div>
                <div class="ss-metric-sub">Integrity or signature failure (<code>result = 0</code>)</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Filter & QR Verification UUID Lookup bar
    col_filter, col_lookup = st.columns([1, 1.35])

    with col_filter:
        st.markdown(
            """
            <div class="ss-panel" style="margin-bottom: 0.85rem;">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Audit Log Filter</div>
                    <span class="ss-panel-tag">FILTER RECORDS</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        outcome_filter = st.selectbox(
            "Filter by Verification Result",
            options=["All Audit Events", "Successful Only (PASS)", "Failed / Tampered Only (FAIL)"],
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col_lookup:
        st.markdown(
            """
            <div class="ss-panel" style="margin-bottom: 0.85rem;">
                <div class="ss-panel-header">
                    <div class="ss-panel-title">Verification UUID / QR Token Lookup</div>
                    <span class="ss-panel-tag">UUID LOOKUP ONLY</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        lookup_id = st.text_input(
            "Enter Verification UUID (from QR Code or Package Metadata)",
            placeholder="e.g., 550e8400-e29b-41d4-a716-446655440000",
            help="QR codes encode only the verification UUID token for database record lookup; they do not independently validate signatures.",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    if lookup_id.strip():
        doc_rec = qrcode_utils.lookup_verification(lookup_id.strip())
        if not doc_rec:
            st.warning(f"No document record found in SQLite for Verification UUID `{lookup_id.strip()}`.")
        else:
            fp = doc_rec.get("public_key_fingerprint", "")
            signer_rec = db.get_signer_record_by_fingerprint(fp)
            if signer_rec is None:
                s_info = "Unregistered Signer"
            else:
                s_info = f"{signer_rec.get('signer_name')} ({signer_rec.get('trust_status')})"
            render_kv_panel(
                title=f"Database Lookup Result for Verification UUID: {lookup_id.strip()}",
                tag="QR / UUID DATABASE RECORD",
                badge_html=status_badge_html("RECORD FOUND", "info"),
                rows=[
                    ("Document ID & Filename", f"#{doc_rec.get('document_id')} — {doc_rec.get('original_filename')}", True),
                    ("Recorded SHA-256 Digest", str(doc_rec.get("sha256_hash", "")), True),
                    ("Public-Key Fingerprint", fp, True),
                    ("Signer Registry Status", s_info, False),
                    ("Signing Timestamp (UTC)", str(doc_rec.get("signing_timestamp", "")), True),
                    (
                        "Security Note",
                        "This lookup retrieves stored signing metadata by UUID; full cryptographic verification requires uploading the signed ZIP package on the Signature Verification page.",
                        False,
                    ),
                ],
            )

    # Apply filter to audit logs
    filtered_logs = logs
    if outcome_filter == "Successful Only (PASS)":
        filtered_logs = [r for r in logs if r.get("verification_result") == 1]
    elif outcome_filter == "Failed / Tampered Only (FAIL)":
        filtered_logs = [r for r in logs if r.get("verification_result") == 0]

    if lookup_id.strip():
        filtered_logs = [
            r for r in filtered_logs if lookup_id.strip().lower() in str(r.get("verification_id", "")).lower()
        ]

    # Render Compact Audit-Log Table
    st.markdown(
        """
        <div class="ss-panel">
            <div class="ss-panel-header">
                <div class="ss-panel-title">Verification Audit Log Table</div>
                <span class="ss-panel-tag">IMMUTABLE AUDIT LOG</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    if not filtered_logs:
        st.caption("No verification audit log entries match the current filter.")
    else:
        rows_html = []
        for entry in filtered_logs:
            log_id = entry.get("log_id", "")
            doc_id = entry.get("document_id", -1)
            fname = entry.get("original_filename") or "External / Unindexed Package"
            verif_uuid = str(entry.get("verification_id", ""))
            ts = str(entry.get("verification_timestamp", ""))
            res_int = entry.get("verification_result", 0)
            failure_reason = entry.get("failure_reason")
            fp = str(entry.get("public_key_fingerprint") or "")
            signer_name = entry.get("signer_name")
            trust_status = entry.get("trust_status")

            doc_display = (
                f"<div><strong>{html.escape(str(fname))}</strong></div>"
                f"<div style='margin-top:0.15rem;'><span class='ss-mono'>Doc #{doc_id}</span> "
                f"<span class='ss-mono'>{html.escape(verif_uuid[:18])}…</span></div>"
            )

            if res_int == 1:
                res_badge = status_badge_html("CRYPTO VALID", "pass")
            else:
                res_badge = status_badge_html("INVALID / FAILED", "fail")

            if signer_name:
                t_badge = (
                    status_badge_html("TRUSTED", "pass")
                    if trust_status == "trusted"
                    else status_badge_html("REVOKED", "fail")
                )
                signer_html = (
                    f"<div><strong>{html.escape(str(signer_name))}</strong> {t_badge}</div>"
                    f"<div style='margin-top:0.15rem;'><span class='ss-mono'>{html.escape(fp[:20])}…</span></div>"
                )
            elif fp:
                signer_html = (
                    f"<div>{status_badge_html('UNREGISTERED', 'warn')}</div>"
                    f"<div style='margin-top:0.15rem;'><span class='ss-mono'>{html.escape(fp[:20])}…</span></div>"
                )
            else:
                signer_html = "<span style='color:#64748B;'>No key record linked</span>"

            if res_int == 1:
                details_html = (
                    "SHA-256 digest &amp; RSA-PSS signature verified successfully."
                )
            else:
                reason_text = html.escape(str(failure_reason or "Signature verification failed"))
                details_html = f"<span style='color:#991B1B; font-weight:600;'>{reason_text}</span>"

            rows_html.append(
                f"<tr>"
                f"<td><span class='ss-mono'>#{log_id}</span></td>"
                f"<td>{doc_display}</td>"
                f"<td><span class='ss-mono'>{html.escape(ts)}</span></td>"
                f"<td>{res_badge}</td>"
                f"<td>{signer_html}</td>"
                f"<td>{details_html}</td>"
                f"</tr>"
            )

        st.markdown(
            f"""
            <div style="overflow-x:auto;">
                <table class="ss-audit-table">
                    <thead>
                        <tr>
                            <th>Log ID</th>
                            <th>Document Identifier</th>
                            <th>Timestamp (UTC)</th>
                            <th>Verification Result</th>
                            <th>Signer Information</th>
                            <th>Verification Details / Diagnostic</th>
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

