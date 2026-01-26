
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime
from bugtrace.reporting.models import ReportContext, Finding, FindingType, Severity, Confidence
from bugtrace.reporting.markdown_generator import MarkdownGenerator

def generate_pre_validation():
    conn = sqlite3.connect("bugtrace.db")
    c = conn.cursor()
    c.execute("SELECT type, severity, confidence_score, details, payload_used, vuln_parameter, attack_url, status FROM finding WHERE scan_id=1")
    rows = c.fetchall()
    conn.close()

    context = ReportContext(target_url="http://127.0.0.1:5150", scan_date=datetime.now())

    for r in rows:
        ftype, severity, score, details, payload, param, url, status = r
        
        # Map Severity
        sev_enum = Severity.MEDIUM
        if severity:
            if severity.upper() == "CRITICAL": sev_enum = Severity.CRITICAL
            elif severity.upper() == "HIGH": sev_enum = Severity.HIGH
            elif severity.upper() == "LOW": sev_enum = Severity.LOW
            elif severity.upper() in ["INFO", "INFORMATION"]: sev_enum = Severity.INFO

        # Map Confidence
        conf_enum = Confidence.TENTATIVE
        if score > 0.9: conf_enum = Confidence.CERTAIN
        elif score > 0.7: conf_enum = Confidence.FIRM

        # Build Finding
        f = Finding(
            title=f"{ftype} in {param or 'URL'}",
            type=FindingType.VULNERABILITY,
            severity=sev_enum,
            confidence=conf_enum,
            description=details or "No details provided.",
            impact="Potential security risk identified by automated scanner.",
            remediation="Review input validation and sanitization logic.",
            metadata={
                "payload": payload,
                "parameter": param,
                "url": url,
                "status": status, # PENDING_VALIDATION
                "reproduction_steps": [
                    f"1. Target URL: {url}", 
                    f"2. Inject payload into parameter '{param}'", 
                    f"3. Payload: {payload}"
                ]
            }
        )
        context.add_finding(f)

    # Generate
    generator = MarkdownGenerator(output_base_dir="reports")
    report_path = generator.generate(context)
    print(f"Report generated at: {report_path}")
    
    # Copy to workspace root for easy access
    src = Path(report_path) / "technical_report.md"
    dst = Path("BUGTRACE_PRE_VALIDATION_REPORT.md")
    shutil.copy(src, dst)
    print(f"Copied to: {dst}")

if __name__ == "__main__":
    generate_pre_validation()
