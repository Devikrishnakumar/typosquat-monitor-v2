"""
app.py
Streamlit dashboard showing live typosquat candidates from SQLite,
sorted by risk score with severity color-coding and a historical trend chart.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import time

from src.storage.db import get_all_candidates, init_db

st.set_page_config(page_title="Typosquat Monitor", layout="wide")

init_db()

st.title("Typosquat & Brand Impersonation Monitor")
st.caption("Live candidates detected from Certificate Transparency logs, sorted by risk")

placeholder = st.empty()


def color_risk_level(level):
    colors = {"HIGH": "background-color: #ff4b4b; color: white;",
              "MEDIUM": "background-color: #ffb84d; color: black;",
              "LOW": "background-color: #4caf50; color: white;"}
    return colors.get(level, "")


while True:
    candidates = get_all_candidates()

    with placeholder.container():
        if not candidates:
            st.info("No candidates detected yet. Waiting for live matches...")
        else:
            df = pd.DataFrame(candidates)

            high = len(df[df["risk_level"] == "HIGH"])
            medium = len(df[df["risk_level"] == "MEDIUM"])
            low = len(df[df["risk_level"] == "LOW"])

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Candidates", len(df))
            col2.metric("HIGH risk", high)
            col3.metric("MEDIUM risk", medium)
            col4.metric("LOW risk", low)

            # Historical trend: detections per day
            df["detected_at"] = pd.to_datetime(df["detected_at"])
            df["date"] = df["detected_at"].dt.date
            trend = df.groupby("date").size().reset_index(name="detections")
            trend = trend.set_index("date")

            st.subheader("Detections Over Time")
            st.line_chart(trend)

            st.subheader("Candidates")
            display_df = df[[
                "id", "domain", "decoded_domain", "matched_brand", "detected_at",
                "is_live", "visual_similarity", "has_login_form",
                "risk_score", "risk_level", "screenshot_path"
            ]]

            styled = display_df.style.map(color_risk_level, subset=["risk_level"])
            st.dataframe(styled, width="stretch", hide_index=True)

    time.sleep(5)
