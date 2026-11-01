import requests
import datetime
import time
import math
from models import Vulnerability
from config import NVD_API_URL, KEV_API_URL, EPSS_API_URL, get_nvd_headers

def extract_vendor(cve_data: dict) -> str:
    try:
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 3 and parts[3] not in ["*", "-"]:
                        return parts[3].capitalize()
    except Exception:
        pass
    return "Unknown"

def fetch_recent_cves(days_back: int = 7) -> list[Vulnerability]:
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=days_back)
    
    # NVD 2.0 Max is 2000 per page. We will cap at 3 pages (6000 CVEs) for performance.
    vulnerabilities = []
    start_index = 0
    results_per_page = 2000
    max_results = 6000
    
    while start_index < max_results:
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }
        
        try:
            response = requests.get(NVD_API_URL, params=params, headers=get_nvd_headers(), timeout=20)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"NVD API Error: {e}")
            break

        raw_vulns = data.get("vulnerabilities", [])
        if not raw_vulns:
            break

        for item in raw_vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description.")
            
            score = None
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
                severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
                severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "UNKNOWN")

            vulnerabilities.append(Vulnerability(
                cve_id=cve_id, description=desc, severity=severity, cvss_score=score, vendor=extract_vendor(cve)
            ))

        total_results = data.get("totalResults", 0)
        start_index += results_per_page
        if start_index >= total_results:
            break
            
        # Respect NVD rate limits (sleep 1s between requests)
        time.sleep(1.0)

    return vulnerabilities

def fetch_kev_list() -> set[str]:
    try:
        response = requests.get(KEV_API_URL, timeout=20)
        response.raise_for_status()
        return {v["cveID"] for v in response.json().get("vulnerabilities", [])}
    except Exception:
        return set()

def enrich_with_epss(cves: list[Vulnerability]) -> dict[str, float]:
    """Fetches EPSS scores in batches of 100 to respect API limits."""
    epss_scores = {}
    cve_ids = [c.cve_id for c in cves]
    
    # Batch processing
    for i in range(0, len(cve_ids), 100):
        batch = ",".join(cve_ids[i:i+100])
        try:
            res = requests.get(f"{EPSS_API_URL}?cve={batch}", timeout=20)
            if res.status_code == 200:
                for item in res.json().get("data", []):
                    epss_scores[item["cve"]] = float(item.get("epss", 0.0))
        except Exception:
            pass
        time.sleep(0.5) # Be kind to FIRST API
        
    return epss_scores

def calculate_composite_risk(cvss: float | None, epss: float | None, is_kev: bool) -> int:
    """Calculates a weighted risk score (0-100)."""
    if is_kev:
        return 100 # Immediate action required
    
    cvss_val = cvss if cvss else 0.0
    epss_val = epss * 10 if epss else 0.0 # Scale EPSS to 0-10 for weighting
    
    # Formula: CVSS (40%) + EPSS (60%)
    score = (cvss_val * 4) + (epss_val * 6)
    return min(100, int(score))

def get_enriched_cves(days_back: int = 7) -> list[Vulnerability]:
    cves = fetch_recent_cves(days_back)
    kev_list = fetch_kev_list()
    epss_map = enrich_with_epss(cves)

    for cve in cves:
        if cve.cve_id in kev_list:
            cve.is_kev = True
        cve.epss_score = epss_map.get(cve.cve_id)
        cve.composite_risk = calculate_composite_risk(cve.cvss_score, cve.epss_score, cve.is_kev)

    return cves
