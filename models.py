from pydantic import BaseModel
from typing import Optional

class Vulnerability(BaseModel):
    cve_id: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_kev: bool = False
    vendor: str = "Unknown"
    composite_risk: int = 0
