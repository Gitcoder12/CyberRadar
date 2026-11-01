import requests
import datetime
import time
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

def fetch_recent_cves(days_back: int = 7, limit: int = 500) -> list[Vulnerability]:
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=days_back)
    
    # GOLDILOCKS LIMIT: 500 CVEs. Fast enough to load instantly, big enough to populate charts.
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": limit
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=get_nvd_headers(), timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"NVD API Error: {e}")
        return []

    vulnerabilities = []
    for item in data.get("vulnerabilities", []):
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
    return vulnerabilities

def fetch_kev_list() -> set[str]:
    try:
        response = requests.get(KEV_API_URL, timeout=10)
        response.raise_for_status()
        return {v["cveID"] for v in response.json().get("vulnerabilities", [])}
    except Exception:
        return set()

def enrich_with_epss(cves: list[Vulnerability]) -> dict[str, float]:
    if not cves: return {}
    
    epss_scores = {}
    # Batch in chunks of 100 to avoid URL length limits
    for i in range(0, len(cves), 100):
        batch = cves[i:i+100]
        cve_ids = ",".join([c.cve_id for c in batch])
        try:
            res = requests.get(f"{EPSS_API_URL}?cve={cve_ids}", timeout=10)
            if res.status_code == 200:
                for item in res.json().get("data", []):
                    epss_scores[item["cve"]] = float(item.get("epss", 0.0))
        except Exception:
            pass
        time.sleep(0.1)
        
    return epss_scores

def calculate_composite_risk(cvss: float | None, epss: float | None, is_kev: bool) -> int:
    if is_kev: return 100
    cvss_val = cvss if cvss else 0.0
    epss_val = epss * 10 if epss else 0.0
    score = (cvss_val * 4) + (epss_val * 6)
    return min(100, int(score))

def get_enriched_cves(days_back: int = 7, limit: int = 500) -> list[Vulnerability]:
    cves = fetch_recent_cves(days_back, limit)
    kev_list = fetch_kev_list()
    epss_map = enrich_with_epss(cves)

    for cve in cves:
        if cve.cve_id in kev_list:
            cve.is_kev = True
        cve.epss_score = epss_map.get(cve.cve_id)
        cve.composite_risk = calculate_composite_risk(cve.cvss_score, cve.epss_score, cve.is_kev)

    return cves
