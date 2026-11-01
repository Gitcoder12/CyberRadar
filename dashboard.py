import streamlit as st
import pandas as pd
from fetcher import get_enriched_cves

st.set_page_config(page_title="CyberRadar", layout="wide", page_icon="🛡️")

st.title("🛡️ CyberRadar — Threat Intelligence")
st.markdown("Real-time CVE tracking with CISA KEV (Known Exploited Vulnerabilities) enrichment.")

# Sidebar
with st.sidebar:
    st.header("Filters")
    days_back = st.slider("Days to look back", 1, 30, 7)
    severity_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
    show_only_kev = st.checkbox("Show ONLY Known Exploited (KEV)", value=False)

# Fetch data (use st.cache_data to prevent re-fetching on every UI click)
@st.cache_data(ttl=3600) # Cache for 1 hour
def load_data(days):
    cves = get_enriched_cves(days)
    return [cve.model_dump() for cve in cves]

with st.spinner("Fetching threat intel from NVD and CISA..."):
    data = load_data(days_back)

if not data:
    st.error("Failed to fetch data. Check your internet connection or API key.")
    st.stop()

df = pd.DataFrame(data)

# Apply filters
if severity_filter:
    df = df[df["severity"].isin(severity_filter)]
if show_only_kev:
    df = df[df["is_kev"] == True]

# Display Metrics
col1, col2, col3 = st.columns(3)
col1.metric("Total CVEs Found", len(df))
col2.metric("Known Exploited (KEV)", df["is_kev"].sum())
col3.metric("Critical Severity", len(df[df["severity"] == "CRITICAL"]))

st.divider()

# Display Data
st.subheader("Vulnerability Feed")

# Highlight KEVs with a red icon
df["KEV Status"] = df["is_kev"].apply(lambda x: "🔴 KEV" if x else "⚪ Standard")

st.dataframe(
    df[["cve_id", "severity", "cvss_score", "KEV Status", "description"]],
    use_container_width=True,
    hide_index=True,
    column_config={
        "cve_id": "CVE ID",
        "severity": "Severity",
        "cvss_score": st.column_config.NumberColumn("CVSS Score", format="%.1f"),
        "KEV Status": "Exploit Status",
        "description": st.column_config.TextColumn("Description", width="large")
    }
)
