import streamlit as st
import requests
import pandas as pd
from datetime import datetime

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CyberRadar | Live Threat Intel",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- CUSTOM STYLING ---
st.markdown("""
    <style>
    .big-font { font-size:24px !important; font-weight: bold; color: #ff4b4b; }
    .stDataFrame { margin-top: 10px; }
    </style>
""", unsafe_allow_html=True)

# --- HEADER ---
st.title("📡 CyberRadar")
st.markdown("### Real-Time Global Threat Intelligence")
st.markdown("Tracking actively exploited vulnerabilities, live malware distribution, and ransomware attacks across the globe.")
st.divider()

# --- DATA FETCHING FUNCTIONS ---

@st.cache_data(ttl=3600) # Cache for 1 hour (CISA updates once a day)
def fetch_cisa():
    """Fetches Known Exploited Vulnerabilities from CISA (US Government)."""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        data = res.json()["vulnerabilities"]
        df = pd.DataFrame(data)
        
        # Keep only the most important columns
        df = df[["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription"]]
        df["dateAdded"] = pd.to_datetime(df["dateAdded"]).dt.strftime('%Y-%m-%d')
        return df.sort_values("dateAdded", ascending=False)
    except Exception as e:
        return pd.DataFrame({"Error": [f"Failed to fetch CISA data: {str(e)}"]})

@st.cache_data(ttl=300) # Cache for 5 minutes (URLhaus updates very fast)
def fetch_urlhaus():
    """Fetches recent malicious URLs from abuse.ch."""
    try:
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        res = requests.post(url, data={"limit": 100}, timeout=10) # Limit to 100 to keep the dashboard fast
        res.raise_for_status()
        data = res.json()
        
        if data.get("query_status") != "ok":
            return pd.DataFrame({"Error": ["URLhaus API is currently unavailable."]})
            
        df = pd.DataFrame(data["urls"])
        # Keep only critical columns
        df = df[["date_added", "url", "threat", "tags", "url_status"]]
        df["date_added"] = pd.to_datetime(df["date_added"]).dt.strftime('%Y-%m-%d %H:%M:%S')
        return df
    except Exception as e:
        return pd.DataFrame({"Error": [f"Failed to fetch URLhaus data: {str(e)}"]})

@st.cache_data(ttl=3600) # Cache for 1 hour
def fetch_ransomware():
    """Fetches recent ransomware victims from Ransomware.live."""
    try:
        url = "https://api.ransomware.live/recentvictims"
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        data = res.json()
        
        df = pd.DataFrame(data)
        # Keep only critical columns
        df = df[["published", "post_title", "group_name", "country"]]
        df["published"] = pd.to_datetime(df["published"]).dt.strftime('%Y-%m-%d')
        return df
    except Exception as e:
        return pd.DataFrame({"Error": [f"Failed to fetch Ransomware data: {str(e)}"]})

# --- UI LAYOUT ---

# Create Tabs
tab1, tab2, tab3 = st.tabs([
    "🚨 CISA: Actively Exploited", 
    "🦠 URLhaus: Live Malware", 
    "🔒 Ransomware: Recent Victims"
])

# Tab 1: CISA
with tab1:
    st.subheader("Known Exploited Vulnerabilities (CISA)")
    st.info("These are vulnerabilities that hackers are actively exploiting *right now* in the wild.")
    df_cisa = fetch_cisa()
    if "Error" in df_cisa.columns:
        st.error(df_cisa["Error"][0])
    else:
        col1, col2 = st.columns(2)
        col1.metric("Total Tracked Exploits", len(df_cisa))
        col2.metric("Latest Exploit Added", df_cisa["dateAdded"].iloc[0])
        st.dataframe(df_cisa, use_container_width=True, hide_index=True)

# Tab 2: URLhaus
with tab2:
    st.subheader("Live Malware Distribution URLs")
    st.warning("These are URLs currently serving malware to unsuspecting users. Do not click them.")
    df_urlhaus = fetch_urlhaus()
    if "Error" in df_urlhaus.columns:
        st.error(df_urlhaus["Error"][0])
    else:
        st.metric("Live Malware URLs Displayed", len(df_urlhaus))
        st.dataframe(df_urlhaus, use_container_width=True, hide_index=True)

# Tab 3: Ransomware
with tab3:
    st.subheader("Recent Ransomware Victims")
    st.error("These are companies and organizations recently hit by ransomware groups.")
    df_ransom = fetch_ransomware()
    if "Error" in df_ransom.columns:
        st.error(df_ransom["Error"][0])
    else:
        st.metric("Recent Victims Listed", len(df_ransom))
        st.dataframe(df_ransom, use_container_width=True, hide_index=True)

# --- FOOTER ---
st.divider()
st.markdown("**CyberRadar** is part of the **TITAN Ecosystem** | Built by CodeCommander | MIT License")
