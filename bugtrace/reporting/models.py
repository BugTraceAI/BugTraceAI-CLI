from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Information"
    SAFE = "Safe"

class Confidence(str, Enum):
    CERTAIN = "Certain"
    FIRM = "Firm"
    TENTATIVE = "Tentative"

class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    RECON_DATA = "recon_data"
    OBSERVATION = "observation"

class Evidence(BaseModel):
    description: str
    content: str
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)

class Finding(BaseModel):
    title: str
    type: FindingType
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.CERTAIN
    description: str
    impact: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    screenshot_path: Optional[str] = None
    evidence: List[Evidence] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    # Validation tracking
    validated: bool = False
    validation_method: Optional[str] = None  # e.g., "Browser + Vision AI", "SQLMap", "Manual"

class ScanStats(BaseModel):
    duration_seconds: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    urls_scanned: int = 0
    forms_tested: int = 0
    payloads_sent: int = 0
    vulns_found: int = 0
    # Validation metrics
    validated_findings: int = 0
    potential_findings: int = 0
    false_positives_blocked: int = 0

class ReportContext(BaseModel):
    scan_id: Optional[int] = None
    target_url: str
    scan_date: datetime = Field(default_factory=datetime.now)
    tool_version: str = "1.0.0"
    stats: ScanStats = Field(default_factory=ScanStats)
    findings: List[Finding] = Field(default_factory=list)
    tech_stack: List[str] = Field(default_factory=list)
    raw_results: Dict[str, Any] = Field(default_factory=dict)
    report_signature: str = "BUGTRACE_AI_REPORT_V5"

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        if finding.type == FindingType.VULNERABILITY and finding.severity not in [Severity.INFO, Severity.SAFE]:
            self.stats.vulns_found += 1
