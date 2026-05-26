import streamlit as st
import pandas as pd
import plotly.express as px
import re
import os
from collections import Counter
from streamlit_autorefresh import st_autorefresh


# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(

    page_title="Secure Cloud Network Monitoring",
    layout="wide"

)

st.title(
    "Secure Cloud-Enabled Network Monitoring Dashboard"
)

# ---------------------------------------------------
# AUTO REFRESH
# ---------------------------------------------------

st_autorefresh(

    interval=30000,
    key="dashboard_refresh"

)

# ---------------------------------------------------
# ALERT FILE PATH
# ---------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(__file__)
)

ALERT_FILE = os.path.join(

    BASE_DIR,
    "alerts",
    "alerts.txt"

)

# ---------------------------------------------------
# CHECK ALERT FILE
# ---------------------------------------------------

if not os.path.exists(ALERT_FILE):

    st.warning("No alerts generated yet.")
    st.stop()

# ---------------------------------------------------
# READ ALERTS
# ---------------------------------------------------

with open(ALERT_FILE, "r") as file:

    lines = file.readlines()

alerts_data = []

# ---------------------------------------------------
# PARSE ALERTS
# ---------------------------------------------------

for line in lines:

    line = line.strip()

    if not line:
        continue

    try:

        # Example:
        # [HIGH] 2026-05-24 18:03:03 - Port scan detected from 10.0.0.5 on Switch1

        severity_match = re.search(

            r"\[(.*?)\]",
            line

        )

        timestamp_match = re.search(

            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
            line

        )

        message_split = line.split(
            " - ",
            1
        )

        severity = (

            severity_match.group(1)

            if severity_match

            else "UNKNOWN"

        )

        timestamp = (

            timestamp_match.group(0)

            if timestamp_match

            else "UNKNOWN"

        )

        message = (

            message_split[1]

            if len(message_split) > 1

            else line

        )

        # ---------------------------------------------------
        # THREAT CLASSIFICATION
        # ---------------------------------------------------

        message_lower = message.lower()

        suspected_threat = "General Threat"

        if "failed login" in message_lower:

            suspected_threat = (
                "Failed Login Attack"
            )

        if "brute-force" in message_lower:

            suspected_threat = (
                "Brute Force Attack"
            )

        if "port scan" in message_lower:

            suspected_threat = (
                "Port Scanning"
            )

        if "ddos" in message_lower or "traffic flood" in message_lower:

            suspected_threat = (
                "DDoS Attack"
            )

        if "beaconing" in message_lower:

            suspected_threat = (
                "Beaconing Activity"
            )

        if "dns flood" in message_lower:

            suspected_threat = (
                "DNS Flood"
            )

        if "blacklisted" in message_lower:

            suspected_threat = (
                "Blacklisted IP Access"
            )

        if "ssh brute-force" in message_lower:

            suspected_threat = (
                "SSH Brute Force"
            )

        if "device anomaly" in message_lower:

            suspected_threat = (
                "Device Behavior Anomaly"
            )

        if "coordinated" in message_lower:

            suspected_threat = (
                "Multi-stage Attack"
            )

        if "correlated" in message_lower:

            suspected_threat = (
                "Suspicious IP Correlation"
            )

        if "denied connections" in message_lower:

            suspected_threat = (
                "Denied Connections Abuse"
            )

        # ---------------------------------------------------
        # STORE DATA
        # ---------------------------------------------------

        alerts_data.append({

            "Timestamp": timestamp,
            "Severity": severity,
            "Suspected Threat": suspected_threat,
            "Message": message

        })

    except Exception:
        pass

# ---------------------------------------------------
# DATAFRAME
# ---------------------------------------------------

df = pd.DataFrame(alerts_data)

if df.empty:

    st.warning("No alerts found.")
    st.stop()

# ---------------------------------------------------
# METRICS
# ---------------------------------------------------

total_alerts = len(df)

critical_alerts = len(

    df[
        df["Severity"] == "CRITICAL"
    ]

)

high_alerts = len(

    df[
        df["Severity"] == "HIGH"
    ]

)

medium_alerts = len(

    df[
        df["Severity"] == "MEDIUM"
    ]

)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Alerts",
    total_alerts
)

col2.metric(
    "Critical Alerts",
    critical_alerts
)

col3.metric(
    "High Severity",
    high_alerts
)

col4.metric(
    "Medium Severity",
    medium_alerts
)

st.markdown("---")

# ---------------------------------------------------
# CHARTS
# ---------------------------------------------------

chart_col1, chart_col2 = st.columns(2)

# ---------------------------------------------------
# SEVERITY DISTRIBUTION
# ---------------------------------------------------

severity_counts = (

    df["Severity"]
    .value_counts()
    .reset_index()

)

severity_counts.columns = [

    "Severity",
    "Count"

]

fig1 = px.pie(

    severity_counts,

    names="Severity",
    values="Count",

    title="Severity Distribution"

)

chart_col1.plotly_chart(

    fig1,
    use_container_width=True,
    key="severity_chart_unique"

)

# ---------------------------------------------------
# THREAT DISTRIBUTION
# ---------------------------------------------------

threat_counter = Counter(

    df["Suspected Threat"]

)

threat_df = pd.DataFrame({

    "Threat": list(
        threat_counter.keys()
    ),

    "Count": list(
        threat_counter.values()
    )

})

threat_df = threat_df.sort_values(

    by="Count",
    ascending=False

)

fig2 = px.bar(

    threat_df,

    x="Count",
    y="Threat",

    orientation="h",

    text="Count",

    title="Top Threat Categories"

)

fig2.update_layout(

    yaxis_title="",
    xaxis_title="Alert Count",

    height=450

)

chart_col2.plotly_chart(

    fig2,
    use_container_width=True,
    key="threat_chart_unique"

)

st.markdown("---")

# ---------------------------------------------------
# RECENT ALERTS TABLE
# ---------------------------------------------------

st.subheader("Recent Alerts")

recent_df = df.iloc[::-1]

# ---------------------------------------------------
# COLOR SEVERITY ROWS
# ---------------------------------------------------

def highlight_severity(row):

    severity = row["Severity"]

    if severity == "CRITICAL":

        return [

            "background-color: #ff4b4b; color: white"

        ] * len(row)

    elif severity == "HIGH":

        return [

            "background-color: #ff944d; color: black"

        ] * len(row)

    elif severity == "MEDIUM":

        return [

            "background-color: #ffd24d; color: black"

        ] * len(row)

    return [""] * len(row)

styled_df = (

    recent_df
    .style
    .apply(
        highlight_severity,
        axis=1
    )

)

st.dataframe(

    styled_df,

    use_container_width=True,

    height=500

)

# ---------------------------------------------------
# LAST UPDATED
# ---------------------------------------------------

st.markdown("---")

st.caption(

    "Dashboard auto-refreshes every 30 seconds"

)