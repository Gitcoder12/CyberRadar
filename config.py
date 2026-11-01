import os

# Set this in Streamlit Secrets or .env
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

def get_nvd_headers():
    headers = {"User-Agent": "CyberRadar/2.0 (Research)"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers
