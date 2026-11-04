"""Reusable cybersecurity-themed UI components and CSS styling for SignSure.

Provides:
- Global CSS injection for a refined deep navy / slate / restrained blue security console.
- Page header banner with module tag, title, and cryptographic parameters badge.
- Compact metric cards, status badges, key-value technical panels, and stage indicators.
"""

from __future__ import annotations

import html
from typing import Dict, List, Optional, Tuple
import streamlit as st


def inject_security_css() -> None:
    """Inject global stylesheet for the SignSure security console interface."""
    st.markdown(
        """
        <style>
        /* Layout & container refinements */
        .block-container {
            padding-top: 1.5rem !important;
            padding-bottom: 2.5rem !important;
            max-width: 1180px !important;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background-color: #0F172A !important;
            border-right: 1px solid #1E293B !important;
        }
        [data-testid="stSidebar"] * {
            color: #E2E8F0 !important;
        }
        [data-testid="stSidebar"] .stRadio label {
            padding: 0.35rem 0.5rem;
            border-radius: 6px;
            font-size: 0.9rem;
            transition: background-color 0.15s ease;
        }
        [data-testid="stSidebar"] .stRadio label:hover {
            background-color: #1E293B;
        }
        
        /* Typography */
        h1, h2, h3, h4 {
            color: #0F172A;
            letter-spacing: -0.015em;
        }
        
        /* Console Header */
        .ss-page-header {
            background: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-left: 4px solid #1E3A8A;
            border-radius: 6px;
            padding: 0.9rem 1.15rem;
            margin-bottom: 1.15rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
        }
        .ss-header-eyebrow {
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #1D4ED8;
            margin-bottom: 0.15rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }
        .ss-header-title {
            font-size: 1.3rem;
            font-weight: 700;
            color: #0F172A;
            margin: 0;
            line-height: 1.25;
        }
        .ss-header-subtitle {
            font-size: 0.84rem;
            color: #475569;
            margin-top: 0.2rem;
        }
        .ss-header-spec {
            background: #F1F5F9;
            border: 1px solid #CBD5E1;
            border-radius: 4px;
            padding: 0.35rem 0.65rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.73rem;
            color: #1E293B;
            white-space: nowrap;
        }

        /* Metric Cards */
        .ss-metric-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.85rem;
            margin-bottom: 1.15rem;
        }
        @media (max-width: 900px) {
            .ss-metric-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        .ss-metric-card {
            background: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-top: 3px solid #1E3A8A;
            border-radius: 6px;
            padding: 0.8rem 1rem;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
        }
        .ss-metric-card.accent-emerald {
            border-top-color: #15803D;
        }
        .ss-metric-card.accent-red {
            border-top-color: #B91C1C;
        }
        .ss-metric-card.accent-indigo {
            border-top-color: #1D4ED8;
        }
        .ss-metric-label {
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748B;
            margin-bottom: 0.25rem;
        }
        .ss-metric-value {
            font-size: 1.55rem;
            font-weight: 700;
            color: #0F172A;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            line-height: 1.15;
        }
        .ss-metric-sub {
            font-size: 0.74rem;
            color: #64748B;
            margin-top: 0.25rem;
        }

        /* Section Panels */
        .ss-panel {
            background: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 0.95rem 1.1rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
        }
        .ss-panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #E2E8F0;
            padding-bottom: 0.5rem;
            margin-bottom: 0.75rem;
        }
        .ss-panel-title {
            font-size: 0.88rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #0F172A;
            margin: 0;
        }
        .ss-panel-tag {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.7rem;
            color: #475569;
            background: #F1F5F9;
            border: 1px solid #CBD5E1;
            padding: 0.12rem 0.45rem;
            border-radius: 4px;
        }

        /* Workflow Pipeline */
        .ss-pipeline {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 0.5rem;
            margin: 0.5rem 0 0.25rem 0;
        }
        @media (max-width: 960px) {
            .ss-pipeline {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        .ss-pipe-step {
            background: #F8FAFC;
            border: 1px solid #CBD5E1;
            border-radius: 5px;
            padding: 0.6rem 0.65rem;
            position: relative;
        }
        .ss-pipe-step.active {
            background: #EFF6FF;
            border-color: #2563EB;
        }
        .ss-pipe-step.done {
            background: #F0FDF4;
            border-color: #16A34A;
        }
        .ss-pipe-num {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.68rem;
            font-weight: 700;
            color: #1D4ED8;
            text-transform: uppercase;
            margin-bottom: 0.15rem;
        }
        .ss-pipe-title {
            font-size: 0.8rem;
            font-weight: 700;
            color: #0F172A;
            margin-bottom: 0.15rem;
        }
        .ss-pipe-desc {
            font-size: 0.72rem;
            color: #475569;
            line-height: 1.3;
        }

        /* Key-Value Technical Grid */
        .ss-kv-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
        }
        .ss-kv-table tr {
            border-bottom: 1px solid #E2E8F0;
        }
        .ss-kv-table tr:last-child {
            border-bottom: none;
        }
        .ss-kv-table th {
            text-align: left;
            width: 210px;
            padding: 0.45rem 0.5rem 0.45rem 0;
            color: #475569;
            font-weight: 600;
            vertical-align: top;
        }
        .ss-kv-table td {
            padding: 0.45rem 0;
            color: #0F172A;
            word-break: break-all;
        }
        .ss-mono {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.78rem;
            background: #F1F5F9;
            border: 1px solid #E2E8F0;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            color: #0F172A;
        }

        /* Status Badges */
        .ss-badge {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            letter-spacing: 0.03em;
            text-transform: uppercase;
        }
        .ss-badge-pass {
            background: #DCFCE7;
            color: #166534;
            border: 1px solid #86EFAC;
        }
        .ss-badge-warn {
            background: #FEF3C7;
            color: #92400E;
            border: 1px solid #FCD34D;
        }
        .ss-badge-fail {
            background: #FEE2E2;
            color: #991B1B;
            border: 1px solid #FCA5A5;
        }
        .ss-badge-info {
            background: #DBEAFE;
            color: #1E40AF;
            border: 1px solid #93C5FD;
        }
        .ss-badge-neutral {
            background: #F1F5F9;
            color: #334155;
            border: 1px solid #CBD5E1;
        }

        /* Prominent Verification Verdict Banner */
        .ss-verdict-banner {
            border-radius: 6px;
            padding: 1rem 1.25rem;
            margin-bottom: 1.1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid;
        }
        .ss-verdict-valid-trusted {
            background: #F0FDF4;
            border-color: #16A34A;
            border-left: 6px solid #15803D;
            color: #14532D;
        }
        .ss-verdict-valid-untrusted {
            background: #FFFBEB;
            border-color: #D97706;
            border-left: 6px solid #B45309;
            color: #78350F;
        }
        .ss-verdict-invalid {
            background: #FEF2F2;
            border-color: #DC2626;
            border-left: 6px solid #B91C1C;
            color: #7F1D1D;
        }
        .ss-verdict-label {
            font-size: 0.72rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 700;
            opacity: 0.85;
        }
        .ss-verdict-title {
            font-size: 1.35rem;
            font-weight: 800;
            letter-spacing: -0.01em;
            margin: 0.1rem 0 0.2rem 0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }
        .ss-verdict-reason {
            font-size: 0.84rem;
            margin: 0;
            line-height: 1.35;
        }

        /* Compact Audit Table */
        .ss-audit-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
            background: #FFFFFF;
        }
        .ss-audit-table thead th {
            background: #F1F5F9;
            color: #334155;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            font-size: 0.7rem;
            padding: 0.55rem 0.65rem;
            border-bottom: 1px solid #CBD5E1;
            text-align: left;
        }
        .ss-audit-table tbody td {
            padding: 0.5rem 0.65rem;
            border-bottom: 1px solid #E2E8F0;
            color: #0F172A;
            vertical-align: middle;
        }
        .ss-audit-table tbody tr:hover {
            background: #F8FAFC;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_page_header(eyebrow: str, title: str, subtitle: str, spec_badge: str = "RSA-2048 / PSS / SHA-256") -> None:
    """Render a compact technical page header."""
    st.markdown(
        f"""
        <div class="ss-page-header">
            <div>
                <div class="ss-header-eyebrow">{html.escape(eyebrow)}</div>
                <div class="ss-header-title">{html.escape(title)}</div>
                <div class="ss-header-subtitle">{html.escape(subtitle)}</div>
            </div>
            <div class="ss-header-spec">{html.escape(spec_badge)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def status_badge_html(label: str, variant: str = "neutral") -> str:
    """Return HTML string for a technical status badge.

    variant: 'pass' | 'warn' | 'fail' | 'info' | 'neutral'
    """
    cls_map = {
        "pass": "ss-badge-pass",
        "warn": "ss-badge-warn",
        "fail": "ss-badge-fail",
        "info": "ss-badge-info",
        "neutral": "ss-badge-neutral",
    }
    cls = cls_map.get(variant, "ss-badge-neutral")
    return f'<span class="ss-badge {cls}">{html.escape(label)}</span>'


def render_kv_panel(
    title: str,
    tag: str,
    rows: List[Tuple[str, str, bool]],
    badge_html: Optional[str] = None,
) -> None:
    """Render a compact technical key-value panel.

    Each tuple in ``rows`` is ``(key_label, value_text_or_html, is_monospace)``.
    If ``is_monospace`` is True, value is escaped and wrapped in ``.ss-mono``.
    If ``is_monospace`` is False, value is escaped plain text (unless it starts with '<span').
    """
    right_html = badge_html if badge_html else f'<span class="ss-panel-tag">{html.escape(tag)}</span>'
    tr_items = []
    for k, v, is_mono in rows:
        k_esc = html.escape(k)
        if is_mono:
            v_rendered = f'<span class="ss-mono">{html.escape(str(v))}</span>'
        elif str(v).startswith("<span"):
            v_rendered = str(v)
        else:
            v_rendered = html.escape(str(v))
        tr_items.append(f"<tr><th>{k_esc}</th><td>{v_rendered}</td></tr>")

    table_html = "".join(tr_items)
    st.markdown(
        f"""
        <div class="ss-panel">
            <div class="ss-panel-header">
                <div class="ss-panel-title">{html.escape(title)}</div>
                <div>{right_html}</div>
            </div>
            <table class="ss-kv-table">
                {table_html}
            </table>
        </div>
        """,
        unsafe_allow_html=True,
    )

