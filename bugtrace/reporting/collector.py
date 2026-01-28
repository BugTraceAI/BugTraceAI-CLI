import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from .models import ReportContext, Finding, FindingType, Severity, Evidence
from bugtrace.utils.logger import get_logger

logger = get_logger("reporting.collector")

class DataCollector:
    """
    Collects and normalizes data from various scan phases into a unified ReportContext.
    """
    def __init__(self, target_url: str, scan_id: Optional[int] = None):
        self.context = ReportContext(target_url=target_url, scan_id=scan_id)

    def add_recon_data(self, recon_results: Dict[str, Any]):
        """Ingests reconnaissance data (products, posts, etc)"""
        if not recon_results:
            return

        # Example: normalizing products found
        files = recon_results.get('files', [])
        if files:
            self.context.add_finding(Finding(
                title=f"Files/Directories Discovered",
                type=FindingType.RECON_DATA,
                severity=Severity.INFO,
                description=f"Found {len(files)} files/directories.",
                metadata={"items": files}
            ))

    def add_vulnerability(self, vuln_data: Dict[str, Any]):
        """Ingests a raw vulnerability dictionary"""
        # Parse and create finding
        finding = self._create_finding_from_vuln_data(vuln_data)

        # Add evidence
        self._add_evidence_to_finding(finding, vuln_data)

        # Deduplication and add to context
        self._deduplicate_and_add_finding(finding, vuln_data)

    def _create_finding_from_vuln_data(self, vuln_data: Dict[str, Any]) -> Finding:
        """Create Finding object from vulnerability data."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "SAFE": Severity.SAFE
        }

        # Default to INFO if unknown
        sev_str = vuln_data.get('severity', 'INFO').upper()
        severity = severity_map.get(sev_str, Severity.INFO)

        # Determine validation status
        is_validated = vuln_data.get('validated', False)

        # Determine validation method
        validation_method = self._determine_validation_method(vuln_data, is_validated)

        return Finding(
            title=vuln_data.get('type', 'Unknown Vulnerability'),
            type=FindingType.VULNERABILITY,
            severity=severity,
            description=vuln_data.get('description', ''),
            impact=vuln_data.get('impact'),
            remediation=vuln_data.get('remediation'),
            cvss_score=vuln_data.get('cvss_score'),
            screenshot_path=vuln_data.get('screenshot_path'),
            validated=is_validated,
            validation_method=validation_method,
            metadata=vuln_data
        )

    def _determine_validation_method(self, vuln_data: Dict[str, Any], is_validated: bool) -> Optional[str]:
        """Determine validation method based on vulnerability type."""
        if not is_validated:
            return None

        vuln_type = (vuln_data.get('type') or '').upper()
        if 'XSS' in vuln_type:
            return "Browser + Vision AI"
        elif 'SQL' in vuln_type:
            return "SQLMap Confirmation"
        elif 'HEADER' in vuln_type or 'CRLF' in vuln_type:
            return "HTTP Response Analysis"
        else:
            return "Automated Verification"

    def _add_evidence_to_finding(self, finding: Finding, vuln_data: Dict[str, Any]):
        """Add evidence items to finding."""
        if 'payload' in vuln_data and vuln_data['payload']:
            finding.evidence.append(Evidence(
                description="Payload causing the issue",
                content=str(vuln_data['payload'])
            ))

        # Add reproduction command as POC
        if 'reproduction' in vuln_data and vuln_data['reproduction']:
            finding.evidence.append(Evidence(
                description="POC Command (Reproduction)",
                content=str(vuln_data['reproduction'])
            ))

    def _deduplicate_and_add_finding(self, finding: Finding, vuln_data: Dict[str, Any]):
        """Check for duplicates and add finding to context."""
        from urllib.parse import urlparse

        # Generate signature
        parsed_url = urlparse(str(vuln_data.get('url', '')))
        path = parsed_url.path
        param = str(vuln_data.get('parameter', ''))
        vtype = str(vuln_data.get('type', '')).upper()

        # Check if already exists
        existing_idx = self._find_existing_vulnerability(vtype, path, param)

        if existing_idx != -1:
            # Handle duplicate
            if self._should_replace_existing(finding, self.context.findings[existing_idx]):
                self.context.findings[existing_idx] = finding
            # Otherwise skip duplicate
            return

        self.context.add_finding(finding)

    def _find_existing_vulnerability(self, vtype: str, path: str, param: str) -> int:
        """Find existing vulnerability with same signature."""
        from urllib.parse import urlparse

        for i, existing in enumerate(self.context.findings):
            if not hasattr(existing, 'metadata'):
                continue

            ex_url = urlparse(str(existing.metadata.get('url', '')))
            ex_path = ex_url.path
            ex_param = str(existing.metadata.get('parameter', ''))
            ex_type = str(existing.title).upper()

            if ex_type == vtype and ex_path == path and ex_param == param:
                return i

        return -1

    def _should_replace_existing(self, new_finding: Finding, existing_finding: Finding) -> bool:
        """Determine if new finding should replace existing one."""
        # Replace if new is validated and old isn't
        if new_finding.validated and not existing_finding.validated:
            return True

        return False

    def ingest_json_file(self, file_path: str):
        """Helper to load legacy JSON files and try to map them"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Naive mapping based on structure observed in generate_report.py
            if 'products' in data:
                 self.context.add_finding(Finding(
                    title="Products Enumerated",
                    type=FindingType.RECON_DATA,
                    severity=Severity.INFO,
                    description=f"Found {len(data['products'])} products via IDOR/Recon.",
                    metadata={"count": len(data['products'])}
                ))
            if 'posts' in data:
                 self.context.add_finding(Finding(
                    title="Blog Posts Enumerated",
                    type=FindingType.RECON_DATA,
                    severity=Severity.INFO,
                    description=f"Found {len(data['posts'])} blog posts via IDOR/Recon.",
                    metadata={"count": len(data['posts'])}
                ))
                
            # Add to raw results just in case
            self.context.raw_results[file_path] = data

        except Exception as e:
            logger.error(f"Error ingesting {file_path}: {e}")

    def add_observation(self, observation: str, metadata: Optional[Dict[str, Any]] = None):
        """Adds a generic security observation or test record to the context."""
        finding = Finding(
            title="Security Observation / Test Record",
            type=FindingType.OBSERVATION,
            severity=Severity.INFO,
            description=observation,
            metadata=metadata or {}
        )
        self.context.add_finding(finding)

    def get_context(self) -> ReportContext:
        return self.context

    def load_from_json(self, file_path: str):
        """Loads a ReportContext from a JSON file, typically engagement_data.json"""
        import json
        with open(file_path, "r") as f:
            data = json.load(f)
            # Reconstruct ReportContext
            self.context = ReportContext(**data)
            # Reconstruct Findings which might be dicts now
            # Pydantic v2 usually handles this if we pass the dict to constructor,
            # but if ReportContext is a Pydantic model it has model_validate.
            # Assuming ReportContext is a Pydantic model:
            # self.context = ReportContext.model_validate(data)
            # Or if it's a simple class, we might need manual reconstruction.
            # Based on view_file models.py it seemed like Pydantic.
            # Let's try simple Pydantic parsing if possible, or manual.
            if hasattr(ReportContext, "model_validate"):
                 self.context = ReportContext.model_validate(data)
            else:
                 # Fallback manual reconstruction if not Pydantic v2
                 self.context = ReportContext(target_url=data.get("target_url", "unknown"))
                 self.context.scan_date = datetime.fromisoformat(data.get("scan_date")) if data.get("scan_date") else datetime.now()
                 self.context.start_time = datetime.fromisoformat(data.get("start_time")) if data.get("start_time") else datetime.now()
                 self.context.end_time = datetime.fromisoformat(data.get("end_time")) if data.get("end_time") else datetime.now()
                 
                 findings = []
                 for f_data in data.get("findings", []):
                     # Reconstruct Enum fields
                     if "type" in f_data and isinstance(f_data["type"], str):
                         # Map string back to FindingType enum if needed, or Pydantic handles it
                         # We'll assume Pydantic handles str -> Enum conversion in constructor
                         pass
                     findings.append(Finding(**f_data))
                 self.context.findings = findings

