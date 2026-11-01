import requests
import datetime
from models import Vulnerability
from config import NVD_API_URL, KEV_API_URL, get_nvd_headers

def fetch_recent_cves(days_back: int = 7) -> list[Vulnerability]:
    """Fetches CVEs from NVD published in the last N days."""
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=days_back)
    
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 2000  # Max allowed per page
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_nvd_headers(), timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error fetching NVD: {e}")
        return []

    vulnerabilities = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        
        # Extract description
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available.")
        
        # Extract metrics (try v3.1 first, then v3.0, then v2)
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"
        
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")

        vulnerabilities.append(Vulnerability(
            cve_id=cve_id,
            description=desc,
            severity=severity,
            cvss_score=score
        ))
        
    return vulnerabilities

def fetch_kev_list() -> set[str]:
    """Fetches the CISA KEV list and returns a set of CVE IDs."""
    try:
        response = requests.get(KEV_API_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"Error fetching KEV: {e}")
        return set()

def get_enriched_cves(days_back: int = 7) -> list[Vulnerability]:
    """Fetches CVEs and flags the ones in the KEV list."""
    cves = fetch_recent_cves(days_back)
    kev_list = fetch_kev_list()
    
    for cve in cves:
        if cve.cve_id in kev_list:
            cve.is_kev = True
            
    return cves
