import asyncio
import os
import sys
import shutil
import json
from pathlib import Path

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.database import get_db_manager
from bugtrace.schemas.db_models import FindingTable as Finding

class MockDB:
    def get_findings_for_scan(self, scan_id):
        # Return mock findings
        findings = []
        
        # 1. Confirmed XSS
        f1 = Finding(
            scan_id=scan_id,
            attack_url="http://example.com/search?q=<script>alert(1)</script>",
            vuln_parameter="q",
            payload_used="<script>alert(1)</script>",
            type="XSS",
            details="Reflected XSS confirmed via CDP execution.",
            severity="HIGH",
            status="VALIDATED_CONFIRMED",
            validator_notes="Verified alert box presence.",
            proof_screenshot_path="logs/mock_capture.png"
        )
        f1.id = 1
        findings.append(f1)
        
        # 2. Manual Review SQLi
        f2 = Finding(
            scan_id=scan_id,
            attack_url="http://example.com/id=1'",
            vuln_parameter="id",
            payload_used="' OR 1=1--",
            type="SQLi",
            details="Potential SQLi error detected.",
            severity="HIGH",
            status="MANUAL_REVIEW_RECOMMENDED",
            validator_notes="Vision model unsure about error message.",
            proof_screenshot_path="logs/mock_capture_2.png"
        )
        f2.id = 2
        findings.append(f2)
        
        return findings

async def test_reporting_v5():
    print("🚀 Starting V5 Reporting Verification...")
    
    # Setup
    output_dir = Path("reports/test_v5_report")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    
    # Mock Data
    scan_id = "test_scan_v5"
    agent = ReportingAgent(scan_id, "http://example.com", output_dir)
    
    # Inject Mock DB
    agent.db = MockDB()
    
    # Create dummy captures
    (output_dir / "captures").mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    with open("logs/mock_capture.png", "w") as f:
        f.write("DUMMY IMAGE")
    
    # Run Generation
    print("📝 Generating deliverables...")
    paths = await agent.generate_all_deliverables()
    
    # Verify Artifacts
    expected_files = [
        "raw_findings.json",
        "validated_findings.json",
        "raw_findings.md",
        "validated_findings.md",
        "final_report.md",
        "engagement_data.js",  # Changed from .json
        "report.html"
    ]
    
    print("\\n🔍 Verifying File Existence:")
    success = True
    for fname in expected_files:
        path = output_dir / fname
        if path.exists():
            print(f"  ✅ Found: {fname}")
        else:
            print(f"  ❌ MISSING: {fname}")
            success = False
            
    if not success:
        print("❌ Verification Failed: Missing files.")
        return

    # Verify Content
    print("\\n🔍 Verifying Content:")
    
    # Check JS structure (manual parse)
    with open(output_dir / "engagement_data.js") as f:
        content = f.read()
        json_str = content.replace("window.BUGTRACE_REPORT_DATA = ", "").rstrip(";")
        data = json.loads(json_str)
        findings = data.get("findings", [])
        if len(findings) > 0 and "markdown_block" in findings[0]:
             print(f"  ✅ JS Data contains 'markdown_block' (Length: {len(findings[0]['markdown_block'])})")
        else:
             print(f"  ❌ JS Data missing 'markdown_block'")
             success = False
             
    # Check Markdown
    with open(output_dir / "validated_findings.md") as f:
        content = f.read()
        if "Confirmed Vulnerabilities" in content and "Use parameterized queries" not in content: # Should contain structure
             print(f"  ✅ Validated Markdown structure looks correct.")
        else:
             print(f"  ⚠️ Check Validated Markdown content.")
             
    # Check HTML Copy Button
    with open(output_dir / "report.html") as f:
        content = f.read()
        if "copyFindingMarkdown" in content and "COPY MD" in content:
             print(f"  ✅ HTML contains Copy Markdown logic.")
        else:
             print(f"  ❌ HTML missing Copy Markdown logic.")
             success = False

    if success:
        print("\\n✨ V5 Reporting Verification SUCCEEDED!")
    else:
        print("\\n❌ V5 Reporting Verification FAILED.")

if __name__ == "__main__":
    asyncio.run(test_reporting_v5())
