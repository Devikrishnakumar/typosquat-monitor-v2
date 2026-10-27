"""
dashboard/app.py

Typosquat & Brand Impersonation Monitor Dashboard.

Pages:
    Dashboard
    Live Detection
    Simulation
    Reports

Simulation is read-only:
    - reads an existing PostgreSQL candidate
    - runs Playwright only after the Trigger button
    - calculates simulation risk
    - generates the PDF only after the Trigger button
    - never inserts or updates PostgreSQL candidate records
"""

import os
import sys
import textwrap
import json
import socket
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st


ROOT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)

sys.path.insert(0, ROOT_DIR)


from src.storage.db import get_all_candidates, init_db
from src.enrichment.evidence_analyzer import run_simulation
from src.enrichment.whois_lookup import get_whois_info
from src.reporting.report_generator import generate_report
from src.alerts.telegram_bot import send_simulation_alert


# =========================================================
# PAGE
# =========================================================

st.set_page_config(
    page_title="Typosquat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# HTML HELPER
# =========================================================

def html_block(value):
    """
    Remove Python indentation before passing HTML to Streamlit.
    This prevents Streamlit from interpreting indented HTML as
    a Markdown code block.
    """
    return textwrap.dedent(value).strip()


def render_html(value):
    st.markdown(
        html_block(value),
        unsafe_allow_html=True,
    )


def check_simulation_dns(domain):
    """Check DNS for the simulation hostname without treating it as a public domain."""
    raw = str(domain or "").strip()
    if not raw:
        return "Not checked", [], "No hostname was provided."

    parsed = urlsplit(raw if "://" in raw else f"http://{raw}")
    hostname = parsed.hostname
    if not hostname:
        return "Not checked", [], "The hostname could not be parsed."

    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records if record and record[4]})
        if addresses:
            return "Resolved", addresses, "The hostname resolved inside the dashboard container's network."
        return "No address returned", [], "DNS returned no address records."
    except socket.gaierror:
        return "Not resolved", [], "The hostname did not resolve from the dashboard container."
    except Exception as exc:
        return "Check error", [], f"DNS check could not complete: {exc}"


@st.fragment(run_every="5s")
def render_certstream_feed():
    """Render recent real certificate events from the worker's shared log."""

    event_path = Path(ROOT_DIR) / "data" / "certstream_events.jsonl"

    if not event_path.exists():
        st.info("Waiting for the first live certificate event.")
        return

    try:
        # The logger maintains a bounded file, so reading it is inexpensive.
        lines = event_path.read_text(encoding="utf-8").splitlines()[-200:]
    except OSError:
        st.warning("The live event log is temporarily unavailable.")
        return

    events = []

    for line in lines:
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        # Do not display simulation data or unrelated log entries.
        if (
            isinstance(event, dict)
            and event.get("source") == "LIVE_CERTSTREAM"
            and event.get("event_type") == "certificate_update"
        ):
            events.append(event)

    if not events:
        st.info("Waiting for real certificate updates from CertStream.")
        return

    latest_events = list(reversed(events[-8:]))

    st.caption(
        f"Latest {len(latest_events)} live certificate events ? "
        "refreshes every 5 seconds"
    )

    for event in latest_events:
        domains = event.get("domains") or []
        if not isinstance(domains, list):
            domains = []

        domains = [str(domain)[:253] for domain in domains[:10]]
        primary_domain = domains[0] if domains else "Domain unavailable"

        matched_domains = event.get("matched_domains") or []
        if not isinstance(matched_domains, list):
            matched_domains = []

        issuer = str(event.get("issuer") or "Not provided")[:160]
        observed_at = str(event.get("observed_at") or "Time unavailable")

        try:
            event_time = datetime.fromisoformat(
                observed_at.replace("Z", "+00:00")
            )
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
            time_label = event_time.astimezone().strftime(
                "%b %d, %H:%M:%S"
            )
        except (ValueError, TypeError):
            time_label = observed_at[:32]

        with st.container(border=True):
            event_cols = st.columns([0.68, 0.32])

            with event_cols[0]:
                st.text(primary_domain)

            with event_cols[1]:
                if event.get("brand_match") and matched_domains:
                    st.markdown("**BRAND MATCH**")
                else:
                    st.caption("No brand match")

            st.caption(f"{time_label} ? {issuer}")

            if len(domains) > 1:
                st.caption(
                    f"{len(domains) - 1} additional certificate domain(s)"
                )

            if matched_domains:
                st.text(
                    "Matched permutation: "
                    + ", ".join(str(item)[:253] for item in matched_domains[:3])
                )


# =========================================================
# ACTIVE STREAMLIT THEME
# =========================================================

try:
    ACTIVE_THEME = st.context.theme.type
except Exception:
    ACTIVE_THEME = "light"

IS_DARK_THEME = ACTIVE_THEME == "dark"


# =========================================================
# CSS
# =========================================================

render_html(
    """
    <style>

    /* =====================================================
       GLOBAL THEME
       ===================================================== */

    .stApp {
        background: var(--background-color, #f5f7fb);
        color: var(--text-color, #252262);
    }

    [data-testid="stAppViewContainer"] {
        background: var(--background-color, #f5f7fb);
        color: var(--text-color, #252262);
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    [data-testid="stSidebar"] {
        background: var(--secondary-background-color, #ffffff);
        border-right: 1px solid rgba(128, 128, 128, 0.16);
    }

    [data-testid="stSidebar"] * {
        color: var(--text-color, #252262) !important;
    }

    /* =====================================================
       TEXT
       ===================================================== */

    .dashboard-title {
        color: var(--text-color, #252262);
        font-size: 34px;
        font-weight: 900;
        letter-spacing: -0.6px;
        margin-bottom: 3px;
    }

    .dashboard-subtitle {
        color: var(--text-color, #777b91);
        opacity: 0.68;
        font-size: 14px;
        margin-bottom: 24px;
    }

    .brand-title {
        color: var(--text-color, #252262);
        font-size: 21px;
        font-weight: 900;
    }

    .brand-subtitle {
        color: var(--text-color, #777b91);
        opacity: 0.65;
        font-size: 11px;
        margin-top: 4px;
    }

    /* =====================================================
       CARDS
       ===================================================== */

    .metric-card {
    box-sizing: border-box;
    width: 100%;
    height: 170px;
    min-height: 170px;
    padding: 20px 14px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    overflow-wrap: anywhere;
    word-break: normal;
}

    .metric-label {
        color: var(--text-color, #7d8297);
        opacity: 0.64;
        font-size: 11px;
        font-weight: 850;
        letter-spacing: 0.55px;
    }

    .metric-value {
        color: var(--text-color, #2d2a70);
        font-size: 28px;
        font-weight: 900;
        margin-top: 8px;
    }

    .metric-small {
        color: var(--text-color, #83889c);
        opacity: 0.62;
        font-size: 11px;
        margin-top: 4px;
    }

    .section-card {
        background: var(--secondary-background-color, #ffffff);
        color: var(--text-color, #252262);
        border: 1px solid rgba(128, 128, 128, 0.16);
        border-radius: 15px;
        padding: 18px;
        margin-bottom: 18px;
        box-shadow: 0 5px 18px rgba(60, 55, 120, 0.055);
    }

    /* =====================================================
       SIMULATION NOTICE
       ===================================================== */

    .simulation-note {
        background: rgba(245, 158, 11, 0.10);
        border-left: 5px solid #f59e0b;
        color: var(--text-color, #715600);
        border-radius: 9px;
        padding: 14px 16px;
        margin-bottom: 20px;
        font-size: 13px;
        line-height: 1.55;
    }

    /* =====================================================
       RISK CARDS
       ===================================================== */

    .risk-box {
    box-sizing: border-box;
    width: 100%;
    height: 170px;
    min-height: 170px;
    padding: 20px 14px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    overflow-wrap: anywhere;
}

    .risk-box-title {
        color: var(--text-color, #777b91);
        opacity: 0.65;
        font-size: 11px;
        font-weight: 850;
        letter-spacing: 0.4px;
    }

    .risk-number {
        color: var(--text-color, #2d2a70);
        font-size: 37px;
        font-weight: 900;
        margin-top: 7px;
    }

    .risk-high {
        color: #dc3545 !important;
        font-weight: 900;
    }

    .risk-medium {
        color: #f59e0b !important;
        font-weight: 900;
    }

    .risk-low {
        color: #22c55e !important;
        font-weight: 900;
    }

    /* =====================================================
       LIVE DETECTION SCANNER
       ===================================================== */

    .scanner-shell {
        position: relative;
        overflow: hidden;

        min-height: 555px;

        display: flex;
        align-items: center;
        justify-content: center;

        margin-bottom: 22px;

        border-radius: 20px;

        border:
            1px solid
            rgba(255, 130, 65, 0.22);

        background:
            radial-gradient(
                circle at center,
                rgba(255, 112, 45, 0.12),
                rgba(10, 8, 18, 0.97) 48%,
                #030307 100%
            );

        box-shadow:
            inset 0 0 90px
                rgba(255, 100, 30, 0.065),
            0 10px 34px
                rgba(0, 0, 0, 0.15);
    }

    .scanner-grid {
        position: absolute;
        inset: 0;

        background-image:
            linear-gradient(
                rgba(255, 130, 65, 0.045) 1px,
                transparent 1px
            ),
            linear-gradient(
                90deg,
                rgba(255, 130, 65, 0.045) 1px,
                transparent 1px
            );

        background-size: 36px 36px;

        opacity: 0.65;
    }

    .scanner-content {
        position: relative;
        z-index: 5;

        width: 100%;

        display: flex;
        align-items: center;
        flex-direction: column;
    }

    .orb-area {
        position: relative;

        width: 360px;
        height: 360px;

        display: flex;
        align-items: center;
        justify-content: center;

        perspective: 1000px;
    }

    .outer-ring {
        position: absolute;

        width: 330px;
        height: 330px;

        border-radius: 50%;

        border:
            1px solid
            rgba(255, 146, 82, 0.35);

        border-top-color:
            rgba(255, 198, 148, 0.90);

        border-left-color:
            rgba(255, 115, 48, 0.68);

        animation:
            ring-spin
            5.5s
            linear
            infinite;

        box-shadow:
            0 0 24px
            rgba(255, 105, 35, 0.20);
    }

    .outer-ring-two {
        position: absolute;

        width: 385px;
        height: 385px;

        border-radius: 50%;

        border:
            1px solid
            rgba(255, 140, 70, 0.17);

        border-right-color:
            rgba(255, 185, 128, 0.60);

        animation:
            ring-spin-reverse
            8s
            linear
            infinite;
    }

    .sphere {
        position: relative;

        width: 270px;
        height: 270px;

        border-radius: 50%;

        transform-style: preserve-3d;

        filter:
            drop-shadow(
                0 0 10px
                rgba(255, 94, 28, 0.85)
            )
            drop-shadow(
                0 0 35px
                rgba(255, 94, 28, 0.38)
            );

        animation:
            sphere-rotate
            7s
            linear
            infinite;
    }

    .sphere-glow {
        position: absolute;
        inset: -28px;

        border-radius: 50%;

        background:
            radial-gradient(
                circle,
                rgba(255, 113, 45, 0.18) 0%,
                rgba(255, 113, 45, 0.08) 45%,
                rgba(255, 113, 45, 0) 73%
            );

        animation:
            glow-pulse
            2.2s
            ease-in-out
            infinite;
    }

    .longitude,
    .latitude {
        position: absolute;

        left: 0;
        right: 0;
        top: 0;
        bottom: 0;

        margin: auto;

        border:
            1.15px solid
            rgba(255, 147, 82, 0.74);

        box-sizing: border-box;

        pointer-events: none;
    }

    .longitude {
        width: 100%;
        height: 100%;
        border-radius: 50%;
    }

    .lon1 {
        transform:
            rotateY(15deg)
            scaleX(0.94);
    }

    .lon2 {
        transform:
            rotateY(30deg)
            scaleX(0.84);
    }

    .lon3 {
        transform:
            rotateY(45deg)
            scaleX(0.70);
    }

    .lon4 {
        transform:
            rotateY(60deg)
            scaleX(0.52);
    }

    .lon5 {
        transform:
            rotateY(78deg)
            scaleX(0.34);
    }

    .lon6 {
        transform:
            rotateY(102deg)
            scaleX(0.34);
    }

    .lon7 {
        transform:
            rotateY(120deg)
            scaleX(0.52);
    }

    .lon8 {
        transform:
            rotateY(135deg)
            scaleX(0.70);
    }

    .lon9 {
        transform:
            rotateY(150deg)
            scaleX(0.84);
    }

    .lon10 {
        transform:
            rotateY(165deg)
            scaleX(0.94);
    }

    .latitude {
        width: 100%;
        height: 48%;
        border-radius: 50%;

        top: 26%;
    }

    .lat1 {
        transform: scaleY(0.25);
    }

    .lat2 {
        transform: scaleY(0.43);
    }

    .lat3 {
        transform: scaleY(0.60);
    }

    .lat4 {
        transform: scaleY(0.77);
    }

    .lat5 {
        transform: scaleY(0.93);
    }

    .sphere-center {
        position: absolute;

        width: 8px;
        height: 8px;

        left: calc(50% - 4px);
        top: calc(50% - 4px);

        border-radius: 50%;

        background: #fff9f2;

        box-shadow:
            0 0 8px #ffffff,
            0 0 22px #ffb07a,
            0 0 48px
                rgba(255, 91, 25, 0.90);

        animation:
            center-pulse
            1.35s
            ease-in-out
            infinite;
    }

    .scanner-status {
        margin-top: 33px;

        color: #fff5ee;

        font-size: 29px;

        font-weight: 900;

        letter-spacing: 7px;

        text-shadow:
            0 0 13px
            rgba(255, 126, 60, 0.55);

        animation:
            status-pulse
            1.7s
            ease-in-out
            infinite;
    }

    .scanner-substatus {
        margin-top: 11px;

        color:
            rgba(255, 225, 209, 0.72);

        font-size: 11px;

        letter-spacing: 2.3px;

        text-align: center;
    }

    @keyframes sphere-rotate {
        from {
            transform:
                rotateY(0deg)
                rotateX(9deg);
        }

        to {
            transform:
                rotateY(360deg)
                rotateX(9deg);
        }
    }

    @keyframes ring-spin {
        from {
            transform: rotate(0deg);
        }

        to {
            transform: rotate(360deg);
        }
    }

    @keyframes ring-spin-reverse {
        from {
            transform: rotate(360deg);
        }

        to {
            transform: rotate(0deg);
        }
    }

    @keyframes glow-pulse {
        0%,
        100% {
            opacity: 0.55;
            transform: scale(0.96);
        }

        50% {
            opacity: 1;
            transform: scale(1.04);
        }
    }

    @keyframes center-pulse {
        0%,
        100% {
            opacity: 0.60;
            transform: scale(0.75);
        }

        50% {
            opacity: 1;
            transform: scale(1.45);
        }
    }

    @keyframes status-pulse {
        0%,
        100% {
            opacity: 0.58;
        }

        50% {
            opacity: 1;
        }
    }

    /* =====================================================
       PIPELINE
       ===================================================== */

    .pipeline-step {
        background: var(--secondary-background-color, #ffffff);
        color: var(--text-color, #252262);

        border:
            1px solid
            rgba(128, 128, 128, 0.16);

        border-radius: 13px;

        padding: 15px 10px;

        text-align: center;

        min-height: 94px;

        box-shadow:
            0 4px 14px
            rgba(50, 48, 110, 0.04);
    }

    .pipeline-number {
        color: #685ee6;
        font-size: 20px;
        font-weight: 900;
    }

    .pipeline-text {
        color: var(--text-color, #686d82);
        opacity: 0.78;
        font-size: 11px;
        font-weight: 750;
        margin-top: 7px;
    }

    

/* CYBER GREEN THEME OVERRIDES */
.stApp {
    background: #07130D;
    color: #E4F8EB;
}
[data-testid="stHeader"] {
    background: rgba(7, 19, 13, 0.96);
}
[data-testid="stSidebar"] {
    background: #08160F;
    border-right: 1px solid #1C633B;
}
[data-testid="stSidebar"] * {
    color: #D8F2E0;
}
.dashboard-title {
    color: #4DFF91 !important;
    text-shadow: 0 0 14px rgba(77, 255, 145, 0.18);
}
.dashboard-subtitle {
    color: #9AB8A4 !important;
}
.stApp [data-testid="stMetric"] {
    background: #0C2115;
    border: 1px solid #247B48;
    border-radius: 12px;
    padding: 14px;
}
.stApp [data-testid="stMetricLabel"] {
    color: #A9CDB5;
}
.stApp [data-testid="stMetricValue"] {
    color: #4DFF91;
}
.stApp [data-testid="stVerticalBlockBorderWrapper"] {
    border-color: #1C633B;
    border-radius: 12px;
}
.stApp h1, .stApp h2, .stApp h3 {
    color: #D8F2E0;
}
.stApp p, .stApp label {
    color: #C4DCCB;
}
.stApp [data-testid="stDataFrame"] {
    border: 1px solid #1C633B;
    border-radius: 8px;
}
.stApp [data-testid="stProgressBar"] > div > div {
    background-color: #4DFF91;
}
.stApp .stButton > button {
    background: #103D25;
    color: #4DFF91;
    border: 1px solid #2AA85C;
    border-radius: 8px;
}
.stApp .stButton > button:hover {
    background: #175532;
    border-color: #4DFF91;
    color: #FFFFFF;
}
.stApp input, .stApp textarea {
    background: #0B1E14;
    color: #E4F8EB;
    border-color: #247B48;
}
@media (max-width: 768px) {
    .dashboard-title {
        font-size: 28px !important;
    }
    .dashboard-subtitle {
        font-size: 13px !important;
    }
}



/* FINAL CYBER GREEN OVERRIDES */
:root {
    color-scheme: dark;
}
.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stMain"] {
    background-color: #07130D !important;
    color: #E4F8EB !important;
}
[data-testid="stHeader"] {
    background-color: #07130D !important;
}
section[data-testid="stSidebar"],
[data-testid="stSidebar"] > div {
    background-color: #08160F !important;
    border-right: 1px solid #247B48 !important;
}
section[data-testid="stSidebar"] * {
    color: #D8F2E0 !important;
}
.dashboard-title {
    color: #4DFF91 !important;
    text-shadow: 0 0 12px rgba(77, 255, 145, 0.18);
}
.dashboard-subtitle {
    color: #A6C7B1 !important;
}
.stApp [data-testid="stVerticalBlockBorderWrapper"] {
    border-color: #24583A !important;
    border-radius: 12px !important;
}
.stApp [data-testid="stMetric"] {
    background: #0B2115 !important;
    border: 1px solid #247B48 !important;
    border-radius: 10px !important;
    padding: 12px !important;
}
.stApp [data-testid="stMetricLabel"] {
    color: #B5D5BF !important;
}
.stApp [data-testid="stMetricValue"] {
    color: #4DFF91 !important;
}
.stApp h1, .stApp h2, .stApp h3 {
    color: #DDF8E6;
}
.stApp [data-testid="stMarkdownContainer"] p,
.stApp [data-testid="stCaptionContainer"] {
    color: #B2CDBA;
}
.stApp [data-testid="stDataFrame"] {
    border: 1px solid #24583A;
    border-radius: 8px;
}
.stApp .stButton > button {
    background: #103D25 !important;
    color: #4DFF91 !important;
    border: 1px solid #2AA85C !important;
    border-radius: 8px !important;
}
.stApp .stButton > button:hover {
    background: #175532 !important;
    border-color: #4DFF91 !important;
}
.stApp input, .stApp textarea {
    background-color: #0B1E14 !important;
    color: #E4F8EB !important;
    border-color: #247B48 !important;
}
.stApp [data-testid="stRadio"] label {
    color: #D8F2E0 !important;
}
@media (max-width: 900px) {
    .dashboard-title {
        font-size: 28px !important;
    }
    [data-testid="stSidebar"] {
        min-width: 0;
    }
}



/* CYBER GREEN TOP BAR FIX */
[data-testid="stAppViewContainer"],
[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
header[data-testid="stHeader"] {
    background: #07130D !important;
    background-color: #07130D !important;
}
[data-testid="stHeader"] {
    border-bottom: 1px solid #1C633B !important;
}
[data-testid="stToolbar"] {
    color: #4DFF91 !important;
}



    /* =====================================================
       CLEAN SIMULATION PAGE POLISH
       ===================================================== */
    [data-testid="stMainBlockContainer"] {
        max-width: 1500px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    .dashboard-title {
        font-size: clamp(28px, 3vw, 38px);
        line-height: 1.15;
        margin-bottom: 8px;
    }

    .dashboard-subtitle {
        font-size: 14px;
        line-height: 1.65;
        margin-bottom: 22px;
    }

    .simulation-note {
        border: 1px solid rgba(59, 130, 246, 0.25);
        border-left: 4px solid #3b82f6;
        border-radius: 14px;
        padding: 18px 20px;
        line-height: 1.8;
        margin: 12px 0 24px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
    }

    .metric-card, .section-card, .risk-box {
        border-radius: 16px;
        box-shadow: 0 6px 22px rgba(15, 23, 42, 0.07);
        transition: border-color .18s ease, transform .18s ease;
    }

    .metric-card {
        padding: 20px;
        min-height: 132px;
    }

    .metric-label, .risk-box-title {
        font-size: 11px;
        letter-spacing: .8px;
        line-height: 1.5;
    }

    .metric-value, .risk-number {
        font-variant-numeric: tabular-nums;
        line-height: 1.25;
    }

    .section-card {
        padding: 20px;
        margin: 8px 0 20px;
    }

    .risk-box {
        min-height: 170px;
        padding: 24px 18px;
    }

    [data-testid="stMetric"] {
        background: var(--secondary-background-color, #fff);
        border: 1px solid rgba(128, 128, 128, .16);
        border-radius: 13px;
        padding: 14px 16px;
        min-height: 96px;
    }

    [data-testid="stMetricLabel"] p {
        font-size: 12px;
        line-height: 1.4;
    }

    [data-testid="stMetricValue"] {
        font-size: clamp(20px, 2vw, 28px);
        font-weight: 750;
        overflow-wrap: anywhere;
    }

    [data-testid="stButton"] > button,
    [data-testid="stDownloadButton"] > button {
        border-radius: 11px;
        min-height: 44px;
        font-weight: 700;
        letter-spacing: .15px;
        transition: transform .15s ease, box-shadow .15s ease;
    }

    [data-testid="stButton"] > button:hover,
    [data-testid="stDownloadButton"] > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 7px 18px rgba(59, 130, 246, .18);
    }

    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid rgba(128, 128, 128, .16);
        border-radius: 12px;
        overflow: hidden;
    }

    [data-testid="stExpander"] {
        border: 1px solid rgba(128, 128, 128, .18);
        border-radius: 12px;
        overflow: hidden;
    }

    h2, h3, h4 {
        letter-spacing: -.25px;
        line-height: 1.35;
    }

    [data-testid="stAlert"] {
        border-radius: 12px;
        line-height: 1.65;
    }

    @media (max-width: 768px) {
        [data-testid="stMainBlockContainer"] {
            padding: 1rem 1rem 2rem;
        }
        .metric-card, .section-card, .risk-box {
            padding: 15px;
        }
        .simulation-note {
            padding: 15px;
        }
    }

</style>
    """
)

# =========================================================
# DARK DASHBOARD OVERRIDES
# =========================================================

if IS_DARK_THEME:

    render_html(
        """
        <style>

        /* -------------------------------------------------
           GLOBAL DARK BACKGROUND
           ------------------------------------------------- */

        html,
        body,
        .stApp,
        [data-testid="stAppViewContainer"],
        [data-testid="stAppViewContainer"] > .main {
            background:
                #1D2030 !important;

            color:
                #F3F4FF !important;
        }

        [data-testid="stHeader"] {
            background:
                #1D2030 !important;
        }

        /* -------------------------------------------------
           SIDEBAR
           ------------------------------------------------- */

        section[data-testid="stSidebar"] {
            background:
                #141724 !important;

            border-right:
                1px solid
                #343A56 !important;
        }

        section[data-testid="stSidebar"] * {
            color:
                #F3F4FF !important;
        }

        section[data-testid="stSidebar"]
        [data-testid="stMarkdownContainer"] {
            color:
                #F3F4FF !important;
        }

        /* -------------------------------------------------
           HEADINGS / TEXT
           ------------------------------------------------- */

        h1,
        h2,
        h3,
        h4,
        h5,
        h6 {
            color:
                #F3F4FF !important;
        }

        p,
        label,
        [data-testid="stCaptionContainer"],
        [data-testid="stMarkdownContainer"] {
            color:
                #D9DDF0 !important;
        }

        .dashboard-title {
            color:
                #F5F6FF !important;
        }

        .dashboard-subtitle {
            color:
                #AEB5CE !important;
            opacity:
                1 !important;
        }

        .brand-title {
            color:
                #F5F6FF !important;
        }

        .brand-subtitle {
            color:
                #AEB5CE !important;
            opacity:
                1 !important;
        }

        /* -------------------------------------------------
           CARDS
           ------------------------------------------------- */

        .metric-card,
        .section-card,
        .risk-box,
        .pipeline-step {
            background:
                #282C40 !important;

            color:
                #F3F4FF !important;

            border:
                1px solid
                #3A405C !important;

            box-shadow:
                0 6px 20px
                rgba(0, 0, 0, 0.18) !important;
        }

        .metric-label {
            color:
                #AEB5CE !important;

            opacity:
                1 !important;
        }

        .metric-value {
            color:
                #F3F4FF !important;
        }

        .metric-small {
            color:
                #A6ADC5 !important;

            opacity:
                1 !important;
        }

        .risk-box-title {
            color:
                #AEB5CE !important;

            opacity:
                1 !important;
        }

        .risk-number {
            color:
                #F3F4FF !important;
        }

        .pipeline-text {
            color:
                #C8CDE0 !important;

            opacity:
                1 !important;
        }

        /* -------------------------------------------------
           STREAMLIT WIDGETS
           ------------------------------------------------- */

        div[data-baseweb="select"] > div {
            background:
                #282C40 !important;

            color:
                #F3F4FF !important;

            border-color:
                #3A405C !important;
        }

        div[data-baseweb="select"] * {
            color:
                #F3F4FF !important;
        }

        div[data-testid="stMultiSelect"] > div {
            background:
                #282C40 !important;

            border-color:
                #3A405C !important;
        }

        div[data-testid="stTextInput"] input {
            background:
                #282C40 !important;

            color:
                #F3F4FF !important;

            border-color:
                #3A405C !important;
        }

        /* -------------------------------------------------
           BUTTONS
           ------------------------------------------------- */

        .stButton > button {
            background:
                #6670E6 !important;

            color:
                #FFFFFF !important;

            border:
                1px solid
                #7B84F5 !important;
        }

        .stButton > button:hover {
            background:
                #737CFF !important;

            color:
                #FFFFFF !important;
        }

        /* Secondary buttons */
        button[kind="secondary"] {
            background:
                #282C40 !important;

            color:
                #F3F4FF !important;

            border-color:
                #3A405C !important;
        }

        /* -------------------------------------------------
           DATAFRAME
           ------------------------------------------------- */

        div[data-testid="stDataFrame"] {
            background:
                #282C40 !important;

            border:
                1px solid
                #3A405C !important;

            border-radius:
                12px !important;

            overflow:
                hidden !important;
        }

        /* -------------------------------------------------
           INFO / WARNING / SUCCESS BOXES
           ------------------------------------------------- */

        div[data-testid="stAlert"] {
            border-radius:
                10px !important;
        }

        /* -------------------------------------------------
           LINKS
           ------------------------------------------------- */

        a {
            color:
                #8A94FF !important;
        }

        a:hover {
            color:
                #AAB1FF !important;
        }

        /* -------------------------------------------------
           CUSTOM INLINE HTML THAT CURRENTLY USES
           var(--text-color)
           ------------------------------------------------- */

        div[style*="var(--text-color"] {
            color:
                #F3F4FF !important;
        }

        </style>
        """
    )



# =========================================================
# SIEM-STYLE NAVY THEME OVERRIDES
# =========================================================

render_html(
    """
    <style>
    :root { color-scheme: dark; }
    html, body, .stApp,
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"],
    [data-testid="stMainBlockContainer"] {
        background: #171a26 !important;
        color: #e6e9f2 !important;
    }
    [data-testid="stHeader"], [data-testid="stToolbar"],
    [data-testid="stDecoration"], [data-testid="stStatusWidget"] {
        background: #171a26 !important;
        color: #e6e9f2 !important;
    }
    [data-testid="stMainBlockContainer"] {
        max-width: 1600px;
        padding-top: 1.2rem;
        padding-bottom: 2rem;
    }
    section[data-testid="stSidebar"],
    [data-testid="stSidebar"] > div {
        background: #111521 !important;
        border-right: 1px solid #343a4c !important;
    }
    [data-testid="stSidebar"] * { color: #e6e9f2 !important; }
    h1, h2, h3, h4, h5, h6,
    [data-testid="stMarkdownContainer"],
    [data-testid="stMarkdownContainer"] p,
    [data-testid="stCaptionContainer"], label {
        color: #e6e9f2 !important;
    }
    .dashboard-title { color: #f4f6fb !important; text-shadow: none !important; }
    .dashboard-subtitle { color: #a6adbf !important; opacity: 1 !important; }
    .brand-title { color: #f4f6fb !important; }
    .brand-subtitle { color: #a6adbf !important; opacity: 1 !important; }
    .metric-card, .section-card, .risk-box, .pipeline-step,
    [data-testid="stVerticalBlockBorderWrapper"] {
        background: #252a39 !important;
        color: #e6e9f2 !important;
        border: 1px solid #363d50 !important;
        border-radius: 9px !important;
        box-shadow: 0 3px 12px rgba(0,0,0,.22) !important;
    }
    .metric-card { height: 132px; min-height: 132px; padding: 16px !important; }
    .metric-label, .risk-box-title { color: #aeb6c9 !important; opacity: 1 !important; }
    .metric-value, .risk-number { color: #f4f6fb !important; }
    .metric-small { color: #aeb6c9 !important; opacity: 1 !important; }
    .risk-high { color: #ff6969 !important; font-weight: 900; }
    .risk-medium { color: #ffad42 !important; font-weight: 900; }
    .risk-low { color: #65c879 !important; font-weight: 900; }
    .simulation-note {
        background: #252a39 !important;
        color: #e6e9f2 !important;
        border: 1px solid #363d50 !important;
        border-left: 4px solid #4f91ff !important;
        border-radius: 9px !important;
    }
    [data-testid="stMetric"] {
        background: #252a39 !important;
        border: 1px solid #363d50 !important;
        border-radius: 8px !important;
        padding: 12px !important;
    }
    [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] p { color: #aeb6c9 !important; }
    [data-testid="stMetricValue"] { color: #f4f6fb !important; }
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        background: #252a39 !important;
        border: 1px solid #363d50 !important;
        border-radius: 8px !important;
        overflow: hidden !important;
    }
    [data-testid="stExpander"] { border: 1px solid #363d50 !important; border-radius: 8px !important; }
    div[data-baseweb="select"] > div,
    div[data-testid="stTextInput"] input,
    div[data-testid="stNumberInput"] input,
    div[data-testid="stTextArea"] textarea {
        background: #252a39 !important;
        color: #f4f6fb !important;
        border-color: #41495e !important;
    }
    .stButton > button, [data-testid="stDownloadButton"] > button {
        background: #343b50 !important;
        color: #f4f6fb !important;
        border: 1px solid #4a536b !important;
        border-radius: 5px !important;
        font-weight: 700 !important;
    }
    .stButton > button:hover, [data-testid="stDownloadButton"] > button:hover {
        background: #414b64 !important;
        border-color: #7797d4 !important;
    }
    a { color: #8bb8ff !important; }
    .scanner-shell { border-color: #343a4c !important; }
    @media (max-width: 768px) {
        [data-testid="stMainBlockContainer"] { padding: 1rem .7rem 2rem; }
        .metric-card { height: auto; min-height: 115px; }
    }
    </style>
    """
)


# =========================================================
# DATABASE
# =========================================================

try:
    init_db()

except Exception as exc:
    st.error(
        f"PostgreSQL initialization failed: {exc}"
    )
    st.stop()


@st.cache_data(ttl=5)
def load_candidates():
    return get_all_candidates()


def refresh_database():
    load_candidates.clear()
    st.rerun()


df = pd.DataFrame(
    load_candidates()
)


# =========================================================
# HELPERS
# =========================================================

def metric_card(
    label,
    value,
    note,
):
    render_html(
        f"""
        <div class="metric-card">

        <div class="metric-label">
        {label}
        </div>

        <div class="metric-value">
        {value}
        </div>

        <div class="metric-small">
        {note}
        </div>

        </div>
        """
    )


def risk_class(level):
    level = str(
        level or "LOW"
    ).upper()

    if level == "HIGH":
        return "risk-high"

    if level == "MEDIUM":
        return "risk-medium"

    return "risk-low"


def clean_value(value):
    if value is None:
        return "N/A"

    if pd.isna(value):
        return "N/A"

    return str(value)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    render_html(
        """
        <div style="padding:8px 4px 20px 4px;">

        <div class="brand-title">
        🛡️ TYPOSQUAT MONITORING
        </div>

        <div class="brand-subtitle">
        Typosquat &amp; Brand Impersonation
        </div>

        </div>
        """
    )

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Live Detection",
            "Simulation",
        ],
        index=0,
    )

    st.divider()

    if st.button(
        "🔄 Refresh PostgreSQL",
        use_container_width=True,
    ):
        refresh_database()

    st.caption(
        "Source: PostgreSQL"
    )

    st.caption(
        "Simulation: read-only"
    )


# =========================================================
# DASHBOARD
# =========================================================

if page == "Dashboard":

    render_html(
        """
        <div class="dashboard-title">Typosquat Dashboard</div>
        <div class="dashboard-subtitle">
        Monitor stored brand-impersonation candidates and incoming certificate events
        </div>
        """
    )

    if df.empty:
        total = 0
        high = 0
        medium = 0
        low = 0
    else:
        total = len(df)
        levels = df["risk_level"].fillna("").astype(str).str.upper()
        high = int((levels == "HIGH").sum())
        medium = int((levels == "MEDIUM").sum())
        low = int((levels == "LOW").sum())

    center, feed = st.columns([2.2, 1], gap="large")

    with center:
        with st.container(border=True):
            st.subheader("Total Matches")
            st.metric("Stored PostgreSQL candidates", total)
            st.caption(
                "This total represents stored candidate records, not every "
                "certificate event received from CertStream."
            )

        risk_cols = st.columns(3, gap="medium")

        with risk_cols[0]:
            with st.container(border=True):
                st.markdown("**HIGH RISK**")
                st.metric("High", high)

        with risk_cols[1]:
            with st.container(border=True):
                st.markdown("**MEDIUM RISK**")
                st.metric("Medium", medium)

        with risk_cols[2]:
            with st.container(border=True):
                st.markdown("**LOW RISK**")
                st.metric("Low", low)

        with st.container(border=True):
            st.subheader("Detection Activity")

            if df.empty:
                st.info("Waiting for matched candidates.")
            elif "detected_at" in df.columns:
                chart_data = df.copy()
                chart_data["detected_at"] = pd.to_datetime(
                    chart_data["detected_at"],
                    errors="coerce",
                    utc=True,
                )
                chart_data = chart_data.dropna(subset=["detected_at"])

                if chart_data.empty:
                    st.info("No valid detection timestamps are available.")
                else:
                    chart_data["date"] = chart_data["detected_at"].dt.date
                    activity = chart_data.groupby("date").size().rename("detections")
                    st.bar_chart(activity, height=220)
            else:
                st.info("Detection timestamps are not available.")

        with st.container(border=True):
            st.subheader("Risk Distribution")

            if total == 0:
                st.info("No stored risk data available.")
            else:
                risk_data = pd.DataFrame(
                    {
                        "Risk": ["HIGH", "MEDIUM", "LOW"],
                        "Count": [high, medium, low],
                    }
                )
                st.bar_chart(risk_data.set_index("Risk"), height=200)

        with st.container(border=True):
            st.subheader("Recent Matched Websites")

            if df.empty:
                st.info("No matched websites yet.")
            else:
                display_columns = [
                    "id",
                    "domain",
                    "matched_brand",
                    "visual_similarity",
                    "has_login_form",
                    "risk_score",
                    "risk_level",
                    "detected_at",
                ]
                available = [col for col in display_columns if col in df.columns]

                if available:
                    st.dataframe(
                        df[available].head(15),
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info("No displayable candidate columns are available.")

    with feed:
        with st.container(border=True):
            st.subheader("Live CertStream Feed")
            st.caption(
                "Incoming certificate events refresh every 5 seconds. "
                "An event is not automatically a confirmed threat."
            )
            render_certstream_feed()


elif page == "Live Detection":

    render_html(
        """
        <div class="dashboard-title">
        Live Detection
        </div>

        <div class="dashboard-subtitle">
        Continuous certificate-transparency and domain monitoring
        </div>
        """
    )

    render_html(
        """
        <div class="scanner-shell">

        <div class="scanner-grid"></div>

        <div class="scanner-content">

        <div class="orb-area">

        <div class="outer-ring"></div>

        <div class="outer-ring-two"></div>

        <div class="sphere">

        <div class="sphere-glow"></div>

        <div class="longitude lon1"></div>
        <div class="longitude lon2"></div>
        <div class="longitude lon3"></div>
        <div class="longitude lon4"></div>
        <div class="longitude lon5"></div>
        <div class="longitude lon6"></div>
        <div class="longitude lon7"></div>
        <div class="longitude lon8"></div>
        <div class="longitude lon9"></div>
        <div class="longitude lon10"></div>

        <div class="latitude lat1"></div>
        <div class="latitude lat2"></div>
        <div class="latitude lat3"></div>
        <div class="latitude lat4"></div>
        <div class="latitude lat5"></div>

        <div class="sphere-center"></div>

        </div>

        </div>

        <div class="scanner-status">
        SEARCHING...
        </div>

        <div class="scanner-substatus">
        CERTIFICATE TRANSPARENCY
        &nbsp;•&nbsp;
        DOMAIN SIGNALS
        &nbsp;•&nbsp;
        LIVE MONITORING
        </div>

        </div>

        </div>
        """
    )

    st.caption(
        "The rotating globe is the visual representation of the "
        "continuous monitoring state. Detection records below come "
        "from PostgreSQL."
    )

    live_count = 0
    login_count = 0
    high_count = 0

    if not df.empty:

        if "is_live" in df.columns:

            live_count = len(
                df[
                    df["is_live"]
                    .fillna(0)
                    .astype(int)
                    == 1
                ]
            )

        if "has_login_form" in df.columns:

            login_count = len(
                df[
                    df["has_login_form"]
                    .fillna(0)
                    .astype(int)
                    == 1
                ]
            )

        if "risk_level" in df.columns:

            high_count = len(
                df[
                    df["risk_level"]
                    .fillna("")
                    .astype(str)
                    .str.upper()
                    == "HIGH"
                ]
            )

    cols = st.columns(4)

    with cols[0]:
        metric_card(
            "DATABASE CANDIDATES",
            len(df),
            "Current PostgreSQL records",
        )

    with cols[1]:
        metric_card(
            "LIVE DOMAINS",
            live_count,
            "Reachable candidates",
        )

    with cols[2]:
        metric_card(
            "LOGIN FORMS",
            login_count,
            "Stored login detections",
        )

    with cols[3]:
        metric_card(
            "HIGH RISK",
            high_count,
            "Stored HIGH records",
        )

    st.write("")

    render_html(
        """
        <div class="section-card">
        """
    )

    st.subheader(
        "Live Detection Results"
    )

    if df.empty:

        st.info(
            "No candidates have been detected yet."
        )

    else:

        selected_levels = st.multiselect(
            "Risk filter",
            [
                "HIGH",
                "MEDIUM",
                "LOW",
            ],
            default=[
                "HIGH",
                "MEDIUM",
                "LOW",
            ],
        )

        live_df = df[
            df["risk_level"]
            .fillna("")
            .astype(str)
            .str.upper()
            .isin(selected_levels)
        ]

        display_columns = [
            "id",
            "domain",
            "matched_brand",
            "detected_at",
            "is_live",
            "visual_similarity",
            "has_login_form",
            "risk_score",
            "risk_level",
            "status",
        ]

        available = [
            col
            for col in display_columns
            if col in live_df.columns
        ]

        st.dataframe(
            live_df[available],
            use_container_width=True,
            hide_index=True,
        )

    render_html(
        """
        </div>
        """
    )



# =========================================================
# SIMULATION
# =========================================================

elif page == "Simulation":

    render_html(
        """
        <div class="dashboard-title">
        Detection Simulation
        </div>

        <div class="dashboard-subtitle">
        Dynamic simulation testing with changing risk scenarios
        </div>
        """
    )

    # Compact control panel: keep instructions readable without a tall banner.
    intro_col, status_col = st.columns([2.2, 1], gap="medium")
    with intro_col:
        st.markdown("### Run a test scenario")
        st.caption(
            "Each trigger creates one simulated match. The preset risk cycle repeats: "
            "LOW → LOW → MEDIUM → MEDIUM → MEDIUM → HIGH."
        )
    with status_col:
        st.markdown(
            "<div style='display:inline-block;padding:8px 12px;border:1px solid #1f9d63;border-radius:10px;color:#5ee6a8;background:#0d2b20;font-weight:700;font-size:12px;letter-spacing:.5px'>● SIMULATION MODE</div>",
            unsafe_allow_html=True,
        )
        st.caption("Session-only results · PostgreSQL is unchanged")


    # =====================================================
    # SESSION STATE
    # =====================================================

    if "simulation_matches" not in st.session_state:
        st.session_state["simulation_matches"] = []

    if "simulation_trigger_count" not in st.session_state:
        st.session_state["simulation_trigger_count"] = 0


    # =====================================================
    # DYNAMIC RISK CYCLE
    # =====================================================

    RISK_CYCLE = [
        {
            "level": "LOW",
            "score": 28,
            "type": "Minor character variation",
            "reason": "This preset represents a small spelling variation with limited similarity signals. The score is configured for demonstration; inspect the evidence checks before interpreting it.",
        },
        {
            "level": "LOW",
            "score": 36,
            "type": "Domain variation",
            "reason": "This preset represents a domain variation with only limited configured suspicion signals. The score is a demonstration value, not a confirmed maliciousness verdict.",
        },
        {
            "level": "MEDIUM",
            "score": 55,
            "type": "Character substitution",
            "reason": "This preset represents a character-substitution pattern with moderate configured suspicion. Domain resemblance alone cannot confirm that a site is malicious.",
        },
        {
            "level": "MEDIUM",
            "score": 64,
            "type": "Brand + keyword variation",
            "reason": "This preset represents a brand-like name combined with an extra keyword. The scenario is assigned a medium score to demonstrate how combined signals can raise suspicion.",
        },
        {
            "level": "MEDIUM",
            "score": 68,
            "type": "Login-oriented variation",
            "reason": "This preset represents a brand-like domain with login-oriented indicators. Review the actual content and visual evidence returned by the analyzer; the scenario itself is not proof of credential theft.",
        },
        {
            "level": "HIGH",
            "score": 86,
            "type": "Strong impersonation scenario",
            "reason": "This preset represents a strong brand-impersonation pattern and is assigned a high demonstration score (86/100). The dashboard shows DNS, reachability, visual and login-related evidence separately; the preset score alone does not prove a real attack.",
        },
    ]


    # =====================================================
    # TRIGGER BUTTON
    # =====================================================

    trigger_col, trigger_hint_col = st.columns([1, 2.2], gap="medium")
    with trigger_col:
        trigger = st.button(
            "🎯 Trigger simulation",
            type="primary",
            use_container_width=True,
        )
    with trigger_hint_col:
        st.caption("Run one test to generate a risk score, explanation, and available evidence checks.")


    # =====================================================
    # ONE CLICK = ONE NEW RESULT
    # =====================================================

    if trigger:
        trigger_number = (
            st.session_state[
                "simulation_trigger_count"
            ] + 1
        )

        st.session_state[
            "simulation_trigger_count"
        ] = trigger_number

        cycle_index = (
            (trigger_number - 1)
            % len(RISK_CYCLE)
        )

        scenario = RISK_CYCLE[
            cycle_index
        ]

        match = {
            "test_number":
                trigger_number,

            "match_id":
                f"SIM-{trigger_number:03d}",

            "domain":
                "simulation-site:8765",

            "display_domain":
                f"simulation-match-{trigger_number:03d}.test",

            "matched_brand":
                "paypal.com",

            "simulation_reference_domain":
                "simulation-site:8765/reference.html",

            "risk_level":
                scenario["level"],

            "risk_score":
                scenario["score"],

            "match_type":
                scenario["type"],

            "risk_reason":
                scenario["reason"],

            "status":
                "SIMULATED MATCH",

            "simulation":
                True,

            "triggered_at":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "report_path":
                None,

            "report_generated":
                False,

            "evidence_status":
                "pending",
        }

        # Keep simulation alerts independent of evidence/report generation.
        match["alert_sent"] = False
        match["alert_status"] = "not_required"

        if str(match.get("risk_level", "")).upper() in {"MEDIUM", "HIGH"}:
            match["alert_status"] = "pending"

            try:
                match["alert_sent"] = bool(
                    send_simulation_alert(match)
                )

                match["alert_status"] = (
                    "sent" if match["alert_sent"] else "failed"
                )

                if match["alert_sent"]:
                    st.success(
                        f"Simulation Telegram alert sent for "
                        f"{match['match_id']}."
                    )
                else:
                    st.warning(
                        f"Telegram alert was not delivered for "
                        f"{match['match_id']}. "
                        "Simulation analysis will continue."
                    )

            except Exception as alert_exc:
                match["alert_status"] = "failed"
                match["alert_error"] = str(alert_exc)

                st.warning(
                    f"Telegram alert failed for {match['match_id']}. "
                    "Simulation analysis will continue."
                )

        try:
            evidence = run_simulation(
                match
            )

            report_path = generate_report(
                match,
                simulation_evidence=evidence,
            )

            match["evidence_status"] = (
                evidence.get(
                    "status",
                    "completed",
                )
            )

            match["evidence_risk_score"] = (
                evidence.get(
                    "risk_score"
                )
            )

            match["evidence_risk_level"] = (
                evidence.get(
                    "risk_level"
                )
            )

            match["visual_similarity"] = (
                evidence.get(
                    "visual_similarity"
                )
            )

            match["login_similarity"] = (
                evidence.get(
                    "login_similarity"
                )
            )

            # Preserve browser evidence separately from scenario values.
            candidate_page = evidence.get("candidate_page") or {}
            match["domain_reachable"] = (
                bool(candidate_page.get("success"))
                if "success" in candidate_page
                else None
            )
            match["domain_reachability_note"] = (
                "Simulation site reachable"
                if match["domain_reachable"] is True
                else "Simulation site not reachable"
                if match["domain_reachable"] is False
                else "Reachability unavailable"
            )

            dns_status, dns_addresses, dns_note = check_simulation_dns(
                match.get("domain")
            )
            match["dns_status"] = dns_status
            match["dns_addresses"] = dns_addresses
            match["dns_note"] = dns_note

            # RDAP registration data is best-effort and may be unavailable.
            try:
                whois_info = get_whois_info(
                    match.get("display_domain") or match["domain"],
                    timeout=8,
                )
                match["registration_date"] = (
                    whois_info.get("creation_date")
                )
                match["registrar"] = whois_info.get("registrar")
            except Exception:
                match["registration_date"] = None
                match["registrar"] = None

            match["report_path"] = (
                report_path
            )

            match["report_generated"] = (
                bool(report_path)
            )

            if report_path:
                st.success(
                    (
                        f"Simulation #{trigger_number} "
                        "completed and PDF report generated."
                    )
                )
            else:
                st.warning(
                    (
                        f"Simulation #{trigger_number} "
                        "completed, but PDF generation failed."
                    )
                )

        except Exception as exc:
            match["evidence_status"] = "failed"
            match["report_generated"] = False
            match["report_error"] = str(exc)

            st.error(
                (
                    f"Simulation #{trigger_number} "
                    f"backend analysis failed: {exc}"
                )
            )

        current_matches = list(
            st.session_state[
                "simulation_matches"
            ]
        )

        current_matches.append(
            match
        )

        current_matches = (
            current_matches[-6:]
        )

        st.session_state[
            "simulation_matches"
        ] = current_matches

        st.toast(
            (
                f"Simulation #{trigger_number}: "
                f"{scenario['level']} scenario analyzed"
            ),
        )

    # CURRENT RESULTS
    # =====================================================

    matches = list(
        st.session_state[
            "simulation_matches"
        ]
    )


    # =====================================================
    # DYNAMIC COUNTERS
    # =====================================================

    total_simulated = len(matches)

    high_count = sum(
        1
        for item in matches
        if item["risk_level"] == "HIGH"
    )

    medium_count = sum(
        1
        for item in matches
        if item["risk_level"] == "MEDIUM"
    )

    low_count = sum(
        1
        for item in matches
        if item["risk_level"] == "LOW"
    )


    # =====================================================
    # DASHBOARD KPI CARDS
    # =====================================================

    st.write("")

    kpi = st.columns(4)


    with kpi[0]:

        metric_card(
            "SIMULATED MATCHES",
            total_simulated,
            "Latest simulation results",
        )


    with kpi[1]:

        metric_card(
            "HIGH RISK",
            high_count,
            "Current simulation count",
        )


    with kpi[2]:

        metric_card(
            "MEDIUM RISK",
            medium_count,
            "Current simulation count",
        )


    with kpi[3]:

        metric_card(
            "LOW RISK",
            low_count,
            "Current simulation count",
        )


    # =====================================================
    # CHARTS
    # =====================================================

    st.write("")

    left, right = st.columns(
        [1.6, 1]
    )


    # -----------------------------------------------------
    # SIMULATION ACTIVITY
    # -----------------------------------------------------

    with left:

        render_html(
            """
            <div class="section-card">
            """
        )

        st.subheader(
            "Simulation Activity"
        )

        if not matches:

            st.info(
                "No simulation triggered yet."
            )

        else:

            activity_data = pd.DataFrame(
                [
                    {
                        "Test":
                            f"#{item['test_number']}",

                        "Risk Score":
                            item["risk_score"],
                    }

                    for item in matches
                ]
            )

            st.bar_chart(
                activity_data.set_index(
                    "Test"
                ),
                height=260,
            )

        render_html(
            """
            </div>
            """
        )


    # -----------------------------------------------------
    # RISK DISTRIBUTION
    # -----------------------------------------------------

    with right:

        render_html(
            """
            <div class="section-card">
            """
        )

        st.subheader(
            "Risk Distribution"
        )

        if not matches:

            st.info(
                "Risk distribution will appear after triggering."
            )

        else:

            distribution = pd.DataFrame(
                {
                    "Risk": [
                        "HIGH",
                        "MEDIUM",
                        "LOW",
                    ],

                    "Count": [
                        high_count,
                        medium_count,
                        low_count,
                    ],
                }
            )

            st.bar_chart(
                distribution.set_index(
                    "Risk"
                ),
                height=260,
            )

        render_html(
            """
            </div>
            """
        )


    # =====================================================
    # CURRENT TRIGGER RESULT
    # =====================================================

    if matches:

        latest = matches[-1]


        st.write("")

        st.subheader(
            "Current Trigger Result"
        )


        result_cols = st.columns(3)


        # -------------------------------------------------
        # CURRENT RISK
        # -------------------------------------------------

        with result_cols[0]:

            render_html(
                f"""
                <div class="risk-box">

                <div class="risk-box-title">
                CURRENT SIMULATION RISK
                </div>

                <div class="risk-number">
                {latest['risk_score']}/100
                </div>

                <div class="{risk_class(
                    latest["risk_level"]
                )}">
                {latest['risk_level']}
                </div>

                </div>
                """
            )


        # -------------------------------------------------
        # TEST NUMBER
        # -------------------------------------------------

        with result_cols[1]:

            metric_card(
                "TRIGGER NUMBER",
                latest[
                    "test_number"
                ],
                "Current simulation",
            )


        # -------------------------------------------------
        # MATCH TYPE
        # -------------------------------------------------

        with result_cols[2]:

            metric_card(
                "MATCH TYPE",
                latest[
                    "match_type"
                ],
                "Current scenario",
            )


        triggered_at = latest.get("triggered_at")

        try:
            triggered_label = (
                datetime.fromisoformat(
                    str(triggered_at).replace("Z", "+00:00")
                )
                .astimezone()
                .strftime("%d %b %Y, %I:%M:%S %p")
            )
        except (ValueError, TypeError):
            triggered_label = "Timestamp unavailable"

        reachable = latest.get("domain_reachable")
        reachability = latest.get("domain_reachability_note")
        if reachability is None:
            reachability = (
                "Simulation site reachable"
                if reachable is True
                else "Simulation site not reachable"
                if reachable is False
                else "Reachability unavailable"
            )

        registration_date = latest.get("registration_date") or "Unavailable"
        registrar = latest.get("registrar") or "Unavailable"

        st.markdown("### Why did the system give this risk score?")
        st.caption(
            "The scenario score is a configured demonstration value. "
            "Evidence findings below are collected separately; a simulation is not proof that a real domain is malicious."
        )

        score_col, level_col, evidence_col = st.columns(3)
        with score_col:
            st.metric("Configured scenario score", f"{latest.get('risk_score', 'N/A')}/100")
        with level_col:
            st.metric("Scenario risk level", str(latest.get("risk_level", "Unavailable")))
        with evidence_col:
            evidence_score = latest.get("evidence_risk_score")
            st.metric(
                "Evidence analyzer score",
                f"{evidence_score}/100" if evidence_score is not None else "Not available",
            )

        st.markdown("#### Scenario explanation")
        st.info(
            f"**Test type:** {latest.get('match_type', 'Unavailable')}\n\n"
            f"**Why this scenario has its configured score:** {latest.get('risk_reason', 'No scenario explanation was recorded.')}\n\n"
            "The score/level above describes the selected simulation preset. The evidence score is the analyzer's separate assessment, when available."
        )

        st.markdown("#### Network and website checks")
        dns_status = latest.get("dns_status", "Not checked")
        dns_addresses = latest.get("dns_addresses") or []
        dns_note = latest.get("dns_note", "DNS check was not recorded.")
        reachable = latest.get("domain_reachable")
        reachability = (
            "Reachable" if reachable is True
            else "Not reachable" if reachable is False
            else "Unknown / not recorded"
        )
        net1, net2, net3 = st.columns(3)
        with net1:
            st.metric("DNS resolution", dns_status)
            st.caption(dns_note)
        with net2:
            st.metric("Simulation website", reachability)
            st.caption("Browser evidence check against the local simulation service.")
        with net3:
            st.metric("Evidence collection", str(latest.get("evidence_status", "Unavailable")).replace("_", " ").title())
            st.caption("Status returned by the evidence analyzer.")

        if dns_addresses:
            st.write("**Resolved IP address(es):** " + ", ".join(str(x) for x in dns_addresses))
        st.caption(
            "This test uses the local Docker simulation hostname. DNS resolution here means it resolved inside the container network; it does not mean the hostname is publicly registered or accessible from the internet."
        )

        st.markdown("#### Evidence indicators")
        visual = latest.get("visual_similarity")
        login = latest.get("login_similarity")
        def format_indicator(value):
            if value is None:
                return "Not available"
            if isinstance(value, (int, float)):
                return f"{value:.1f}%" if 0 <= value <= 100 else str(value)
            return str(value)

        indicators = [
            {"Check": "Visual similarity", "Observed result": format_indicator(visual), "What it means": "Compares the captured page with the reference page; unavailable means no usable comparison was returned."},
            {"Check": "Login/content similarity", "Observed result": format_indicator(login), "What it means": "Shows the analyzer's login-related similarity signal when available; it is not proof of credential theft."},
            {"Check": "Domain registration date", "Observed result": str(latest.get("registration_date") or "Unavailable"), "What it means": "Registration lookup may be unavailable for local or reserved simulation hostnames."},
            {"Check": "Registrar", "Observed result": str(latest.get("registrar") or "Unavailable"), "What it means": "Provided only when registration lookup returns a registrar."},
        ]
        st.dataframe(pd.DataFrame(indicators), use_container_width=True, hide_index=True)

        st.markdown("#### Final interpretation")
        risk_level = str(latest.get("risk_level", "UNKNOWN")).upper()
        if risk_level == "HIGH":
            st.warning(
                "**High-risk demonstration scenario:** the configured scenario is intended to represent a strong impersonation pattern. "
                "Review the evidence indicators above to see which checks returned data; do not treat the preset score alone as proof of a real attack."
            )
        elif risk_level == "MEDIUM":
            st.warning(
                "**Medium-risk demonstration scenario:** the configured scenario represents a moderate or combined set of suspicious signals. "
                "Review available evidence before drawing a conclusion."
            )
        else:
            st.success(
                "**Low-risk demonstration scenario:** the configured scenario represents limited similarity signals. "
                "Low risk does not guarantee that a domain is safe."
            )

        st.markdown("#### Simulation details")
        with st.expander("View identifiers and timestamps"):
            st.write(f"**Simulation ID:** {latest.get('match_id', 'Unavailable')}")
            st.write(f"**Simulated hostname:** {latest.get('domain', 'Unavailable')}")
            st.write(f"**Display-only hostname:** {latest.get('display_domain', 'Unavailable')}")
            st.write(f"**Matched brand:** {latest.get('matched_brand', 'Unavailable')}")
            st.write(f"**Triggered at:** {triggered_label}")
            st.write(f"**PDF report:** {'Generated' if latest.get('report_generated') else 'Not generated'}")



    # =====================================================
    # GENERATED MATCHES
    # =====================================================

    st.write("")

    # =====================================================
    # GENERATED PDF REPORT
    # =====================================================

    if matches:

        latest_report_match = matches[-1]

        latest_report_path = (
            latest_report_match.get("report_path")
        )

        if (
            latest_report_path
            and latest_report_match.get("report_generated")
        ):

            try:
                with open(
                    latest_report_path,
                    "rb",
                ) as pdf_file:

                    pdf_bytes = pdf_file.read()

                report_name = (
                    str(latest_report_path)
                    .replace("\\", "/")
                    .rsplit("/", 1)[-1]
                )

                render_html(
                    f"""
                    <div class="simulation-note">

                    <strong>
                    REPORT GENERATED
                    </strong>

                    <br><br>

                    Simulation:
                    <strong>
                    {latest_report_match["match_id"]}
                    </strong>

                    <br>

                    Report:
                    <strong>
                    {report_name}
                    </strong>

                    <br><br>

                    The backend completed the evidence analysis
                    and generated the PDF report successfully.

                    </div>
                    """
                )

                st.download_button(
                    "DOWNLOAD PDF REPORT",
                    data=pdf_bytes,
                    file_name=report_name,
                    mime="application/pdf",
                    use_container_width=True,
                    key=(
                        "download_pdf_"
                        + latest_report_match["match_id"]
                    ),
                )

            except Exception as report_error:

                st.error(
                    "PDF generated, but could not be opened: "
                    + str(report_error)
                )

    st.subheader(
        "Generated Simulation Matches"
    )


    if not matches:

        render_html(
            """
            <div class="section-card">

            <div style="
                text-align:center;
                padding:40px 10px;
                color:var(--text-color,#777);
                opacity:0.75;
            ">

            <div style="
                font-size:42px;
                margin-bottom:12px;
            ">
            🎯
            </div>

            <strong>
            Ready for simulation
            </strong>

            <br><br>

            No matches have been generated yet.

            </div>

            </div>
            """
        )


    else:

        for item in reversed(matches):

            css_class = risk_class(
                item["risk_level"]
            )

            render_html(
                f"""
                <div class="section-card"
                     style="
                        border-left:
                        5px solid #685ee6;
                     ">

                <div style="
                    display:flex;
                    justify-content:space-between;
                    align-items:center;
                    gap:20px;
                ">

                <div>

                <div style="
                    font-size:17px;
                    font-weight:850;
                    color:
                        var(
                            --text-color,
                            #252262
                        );
                ">

                {item["match_id"]}
                &nbsp;•&nbsp;
                {item["domain"]}

                </div>

                <div style="
                    margin-top:7px;
                    color:
                        var(
                            --text-color,
                            #777
                        );
                    opacity:0.75;
                    font-size:12px;
                ">

                Matched:
                {item["matched_brand"]}

                &nbsp;•&nbsp;

                {item["match_type"]}

                </div>

                <div style="
                    margin-top:7px;
                    color:#685ee6;
                    font-size:10px;
                    font-weight:850;
                ">

                🎬 SIMULATED MATCH
                &nbsp;•&nbsp;
                TRIGGER #{item["test_number"]}

                </div>

                </div>


                <div style="
                    text-align:right;
                    min-width:100px;
                ">

                <div style="
                    font-size:23px;
                    font-weight:900;
                    color:
                        var(
                            --text-color,
                            #252262
                        );
                ">

                {item["risk_score"]}/100

                </div>

                <div class="{css_class}">
                {item["risk_level"]}
                </div>

                </div>

                </div>

                </div>
                """
            )


    # =====================================================
    # SIX-TRIGGER CYCLE INDICATOR
    # =====================================================

    cycle_position = (
        (
            st.session_state[
                "simulation_trigger_count"
            ] - 1
        )
        % 6
        + 1
        if st.session_state[
            "simulation_trigger_count"
        ] > 0
        else 0
    )


    if cycle_position == 6:

        render_html(
            """
            <div class="simulation-note">

            <strong>
            ✅ RISK CYCLE COMPLETE
            </strong>

            <br><br>

            Current six-test distribution:

            <strong>
            LOW: 2
            &nbsp;•&nbsp;
            MEDIUM: 3
            &nbsp;•&nbsp;
            HIGH: 1
            </strong>

            <br><br>

            The next trigger starts the sequence again
            from LOW.

            </div>
            """
        )



