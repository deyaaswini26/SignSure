"""SignSure Streamlit entry point.

Presents a cybersecurity-inspired academic console with five core modules:
1. Overview (Document Security Console)
2. Digital Signing (5-Stage Cryptographic Workflow)
3. Signature Verification (Checks A: Integrity, B: Authenticity, C: Signer Trust)
4. Trusted Signers (Public-Key Registry & Revocation Management)
5. Verification History (Immutable Audit-Log Table & UUID Lookup)
"""

from __future__ import annotations

import streamlit as st

from app import db
from app.ui import (
    overview,
    sign_document,
    verify_document,
    trusted_signers,
    verification_history,
)
from app.ui.components import inject_security_css

# Configure page layout before any other Streamlit calls
st.set_page_config(
    page_title="SignSure // Cryptographic Document Security Console",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)

# Initialise the SQLite database (idempotent)
db.init_db()

# Inject global cybersecurity console stylesheet
inject_security_css()


def _render_sidebar() -> str:
    """Render the deep-navy technical navigation sidebar and return the selected module."""
    with st.sidebar:
        st.markdown(
            """
            <div style="padding: 0.25rem 0 0.85rem 0; border-bottom: 1px solid #1E293B; margin-bottom: 0.85rem;">
                <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.68rem; letter-spacing: 0.1em; color: #60A5FA !important; font-weight: 700;">
                    DATA &amp; INFORMATION SECURITY
                </div>
                <div style="font-size: 1.25rem; font-weight: 800; color: #F8FAFC !important; letter-spacing: -0.01em; margin-top: 0.15rem;">
                    SIGNSURE
                </div>
                <div style="font-size: 0.76rem; color: #94A3B8 !important; margin-top: 0.15rem;">
                    Digital Signature &amp; Public-Key Trust Verification System
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        selected = st.radio(
            "SECURITY MODULES",
            options=(
                "Overview",
                "Digital Signing",
                "Signature Verification",
                "Trusted Signers",
                "Verification History",
            ),
            index=0,
        )

        # Compact cryptographic specification panel in sidebar footer
        st.markdown(
            """
            <div style="margin-top: 1.25rem; padding-top: 0.85rem; border-top: 1px solid #1E293B; font-size: 0.73rem; line-height: 1.45;">
                <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.66rem; letter-spacing: 0.08em; color: #93C5FD !important; font-weight: 700; margin-bottom: 0.35rem;">
                    ACTIVE CRYPTO PROFILE
                </div>
                <div style="color: #CBD5E1 !important;"><strong>Asymmetric:</strong> RSA-2048 (e=65537)</div>
                <div style="color: #CBD5E1 !important;"><strong>Scheme:</strong> RSA-PSS (MGF1)</div>
                <div style="color: #CBD5E1 !important;"><strong>Digest:</strong> SHA-256 (256-bit)</div>
                <div style="color: #CBD5E1 !important;"><strong>Fingerprint:</strong> SHA-256(PEM)</div>
                <div style="color: #CBD5E1 !important;"><strong>Storage:</strong> SQLite3 Local Audit</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return selected


page = _render_sidebar()

if page == "Overview":
    overview.render()
elif page == "Digital Signing":
    sign_document.render()
elif page == "Signature Verification":
    verify_document.render()
elif page == "Trusted Signers":
    trusted_signers.render()
elif page == "Verification History":
    verification_history.render()
