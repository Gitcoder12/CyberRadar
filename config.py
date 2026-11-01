import os

# Get your free NVD API key here: https://nvd.nist.gov/developers/request-an-api-key
# Store it in your environment variables, NEVER hardcode it.
NVD_API_KEY = os.getenv("NVD_API_KEY", "") 

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Headers for NVD API (needed if you have an API key)
def get_nvd_headers():
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers
