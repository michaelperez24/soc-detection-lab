"""Run with: streamlit run app.py"""
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from detections import detect, load_events

st.set_page_config(page_title="SOC Executive Dashboard", layout="wide")
st.title("SOC Executive Dashboard")
st.caption("Portfolio demonstration • synthetic events • rule-based detections; not a production SIEM")
with st.sidebar:
    st.header("Data and detection")
    uploaded = st.file_uploader("Upload event CSV", type="csv")
    threshold = st.slider("Failed logins in window", 2, 15, 5)
    minutes = st.slider("Window (minutes)", 1, 60, 10)
try:
    events = load_events(uploaded if uploaded is not None else Path(__file__).parent / "data/sample_events.csv")
    alerts = detect(events, threshold, minutes)
except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as exc:
    st.error(f"Unable to process events: {exc}")
    st.stop()

view = st.radio("View", ["Executive", "Analyst"], horizontal=True)
if view == "Executive":
    st.subheader("Operational snapshot")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events ingested", len(events))
    c2.metric("Alerts generated", len(alerts))
    c3.metric("Critical alerts", int((alerts.severity == "Critical").sum()) if not alerts.empty else 0)
    c4.metric("Unique targeted users", events.target_user.nunique())
    if not alerts.empty:
        left, right = st.columns(2)
        with left:
            counts = alerts.severity.value_counts().rename_axis("Severity").reset_index(name="Alerts")
            st.plotly_chart(px.bar(counts, x="Severity", y="Alerts", title="Alerts by severity"), use_container_width=True)
        with right:
            timeline = alerts.assign(hour=alerts.timestamp.dt.floor("h")).groupby("hour").size().reset_index(name="Alerts")
            st.plotly_chart(px.line(timeline, x="hour", y="Alerts", markers=True, title="Alert timeline (UTC)"), use_container_width=True)
        st.markdown("**Executive summary:** Review critical login activity first, validate affected accounts, then triage phishing and blocked malware reports. These are suggestions based on demo rules, not confirmed incidents.")
    else:
        st.info("No alerts matched the current detection settings.")
    st.caption("Investigation, false-positive and escalation counts; MTTD/MTTR; endpoint coverage; vulnerability trends; and risk scores require case, asset, and vulnerability data. This sample does not invent them.")
else:
    st.subheader("Alert triage")
    severities = st.multiselect("Severity", ["Critical", "High", "Medium"], default=["Critical", "High", "Medium"])
    filtered = alerts[alerts.severity.isin(severities)] if not alerts.empty else alerts
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button("Download alerts CSV", filtered.to_csv(index=False), "soc_alerts.csv", "text/csv")
    st.subheader("Source events")
    st.dataframe(events, use_container_width=True, hide_index=True)
    st.caption("All alerts begin in New status. Confirm context and disposition in a case-management workflow before treating them as incidents.")
