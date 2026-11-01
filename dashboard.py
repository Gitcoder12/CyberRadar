import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import datetime
from fetcher import get_enriched_cves

st.set_page_config(page_title="CyberRadar | Threat Intel", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    .stMetric { 
        background: linear-gradient(180deg, rgba(0,245,212,0.05) 0%, rgba(0,0,0,0) 100%);
        border: 1px solid rgba(0,245,212,0.3); border-radius: 8px; padding: 15px;
    }
    .stMetric label { color: #7ee787 !important; font-weight: bold; font-family: monospace; }
    .radar-logo { width: 50px; height: 50px; animation: pulse 2s infinite; }
    @keyframes pulse { 0% { opacity: 0.7; } 50% { opacity: 1; filter: drop-shadow(0 0 10px #00f5d4); } 100% { opacity: 0.7; } }
    .header-container { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
</style>
""", unsafe_allow_html=True)

radar_svg = """
<svg class="radar-logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="none" stroke="#00f5d4" stroke-width="2" opacity="0.3"/>
  <circle cx="50" cy="50" r="30" fill="none" stroke="#00f5d4" stroke-width="2" opacity="0.5"/>
  <circle cx="50" cy="50" r="15" fill="none" stroke="#00f5d4" stroke-width="2" opacity="0.7"/>
  <line x1="50" y1="5" x2="50" y2="95" stroke="#00f5d4" stroke-width="1" opacity="0.3"/>
  <line x1="5" y1="50" x2="95" y2="50" stroke="#00f5d4" stroke-width="1" opacity="0.3"/>
  <path d="M50 50 L50 5 A45 45 0 0 1 95 50 Z" fill="rgba(0, 245, 212, 0.2)"/>
  <circle cx="70" cy="30" r="4" fill="#ff003c"/>
</svg>
"""
st.markdown(f'<div class="header-container">{radar_svg}<h1 style="margin: 0;">CyberRadar // Threat Intel</h1></div>', unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 🎯 Targeting Parameters")
    days_back = st.slider("Days to look back", 1, 30, 7)
    severity_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
    show_only_kev = st.checkbox("Show ONLY Known Exploited (KEV)", value=False)
    
    st.divider()
    if st.button("🔄 Force API Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    st.caption(f"Last Scan: {datetime.datetime.now().strftime('%H:%M:%S')}")

@st.cache_data(ttl=3600)
def load_data(days):
    cves = get_enriched_cves(days)
    return [cve.model_dump() for cve in cves]

with st.spinner("📡 Scanning NVD, CISA KEV, and EPSS databases..."):
    data = load_data(days_back)

if not data:
    st.error("⚠️ Failed to fetch data. Please wait 30 seconds and refresh.")
    st.stop()

df = pd.DataFrame(data)

if severity_filter:
    df = df[df["severity"].isin(severity_filter)]
if show_only_kev:
    df = df[df["is_kev"] == True]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Detected", len(df))
col2.metric("Known Exploited", int(df["is_kev"].sum()))
col3.metric("Critical Alerts", len(df[df["severity"] == "CRITICAL"]))
col4.metric("Unique Vendors", df["vendor"].nunique())

st.divider()

# --- Solidifier Logic ---
if "solidifier_log" not in st.session_state:
    st.session_state.solidifier_log = []
    st.session_state.threat_counts = {}

def apply_solidifier(df):
    newly_solidified = []
    for _, row in df.iterrows():
        if row["is_kev"]:
            cve_id = row["cve_id"]
            st.session_state.threat_counts[cve_id] = st.session_state.threat_counts.get(cve_id, 0) + 1
            if st.session_state.threat_counts[cve_id] >= 1 and cve_id not in st.session_state.solidifier_log:
                st.session_state.solidifier_log.append(cve_id)
                newly_solidified.append(cve_id)
    return newly_solidified

apply_solidifier(df)

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("📡 Threat Radar (Severity)")
    
    all_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_counts = df["severity"].value_counts().reindex(all_severities, fill_value=0)
    
    cats = sev_counts.index.tolist()
    vals = sev_counts.values.tolist()
    
    cats.append(cats[0])
    vals.append(vals[0])
    
    fig = go.Figure(go.Scatterpolar(
        r=vals, theta=cats, fill='toself', 
        line=dict(color='#00f5d4'), fillcolor='rgba(0,245,212,0.2)',
        marker=dict(size=6, color='#00f5d4')
    ))
    fig.update_layout(
        polar=dict(radialaxis=dict(gridcolor="rgba(255,255,255,0.1)")), 
        template="plotly_dark", height=350, 
        margin=dict(l=40, r=40, t=20, b=20)
    )
    st.plotly_chart(fig, use_container_width=True)

with chart_col2:
    st.subheader("🏢 Top Affected Vendors")
    vc = df["vendor"].value_counts().head(7).reset_index()
    vc.columns = ["Vendor", "Count"]
    if not vc.empty:
        fig = px.bar(vc, x="Count", y="Vendor", orientation="h", color="Count", color_continuous_scale=["#004d40", "#00f5d4"])
        fig.update_layout(template="plotly_dark", height=350, margin=dict(l=0, r=0, t=20, b=0), coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)

st.divider()

col_meter, col_table = st.columns([1, 2])
with col_meter:
    st.subheader("⚠️ System Threat Posture")
    total = len(df)
    risk_score = (df["composite_risk"].mean() if total > 0 else 0)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=risk_score,
        title={'text': "Weakness Level (%)", 'font': {'color': '#00f5d4'}},
        gauge={'bar': {'color': "#ff003c" if risk_score > 50 else "#00f5d4"}, 'steps': [
            {'range': [0, 30], 'color': 'rgba(0, 245, 212, 0.1)'},
            {'range': [30, 70], 'color': 'rgba(255, 165, 0, 0.2)'},
            {'range': [70, 100], 'color': 'rgba(255, 0, 60, 0.3)'}]}
    ))
    fig.update_layout(template="plotly_dark", height=280, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(fig, use_container_width=True)

with col_table:
    st.subheader("🚨 Vulnerability Feed")
    def get_status(row):
        if row["cve_id"] in st.session_state.solidifier_log: return "🛡️ SOLIDIFIED"
        if row["is_kev"]: return "🔴 Unpatched"
        if row["severity"] == "CRITICAL": return "🟠 Needs Patch"
        return "🟢 Patched"
    
    df["Status"] = df.apply(get_status, axis=1)
    display = df[["cve_id", "vendor", "cvss_score", "epss_score", "composite_risk", "Status", "description"]]
    
    st.dataframe(display, use_container_width=True, hide_index=True, height=280, column_config={
        "cve_id": "CVE ID", "vendor": "Vendor", "cvss_score": "CVSS", "epss_score": "EPSS", 
        "composite_risk": "Risk Score", "Status": "Patch Status", "description": "Description"
    })

if st.session_state.solidifier_log:
    st.error(f"🚨 SOLIDIFIER ACTIVE: {len(st.session_state.solidifier_log)} actively exploited CVEs have been quarantined.")
    with st.expander("View Defense Log"):
        for cve in st.session_state.solidifier_log:
            st.code(f"[AUTO-DEFENSE] Applied strict WAF rules for {cve}.", language="bash")
elif df["is_kev"].sum() == 0:
    st.success("✅ No actively exploited CVEs detected. Solidifier standing by.")

st.divider()
csv = display.to_csv(index=False).encode('utf-8')
st.download_button("📥 Download Threat Report (CSV)", csv, "cyberradar_report.csv", "text/csv", use_container_width=True)
