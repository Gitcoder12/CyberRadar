from pydantic import BaseModel
from typing import Optional

class Vulnerability(BaseModel):
    cve_id: str
    description: str
    severity: str
    cvss_score: Optional[float]
    is_kev: bool = False  # Is it in the CISA Known Exploited Vulnerabilities list?
