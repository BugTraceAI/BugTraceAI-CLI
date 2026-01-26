import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bugtrace.reporting.collector import DataCollector
from bugtrace.reporting.generator import HTMLGenerator
from bugtrace.reporting.models import Finding
import datetime

def test_reporting():
    print("Testing reporting module...")
    
    # 1. Create Collector
    url = "https://example.com"
    collector = DataCollector(url)
    
    # 2. Add Mock Findings
    vuln = {
        "type": "SQL Injection",
        "severity": "HIGH",
        "description": "SQL Injection found in param 'id'",
        "payload": "' OR 1=1--",
        "impact": "Database Dump",
        "remediation": "Use prepared statements"
    }
    collector.add_vulnerability(vuln)
    
    collector.add_recon_data({"files": ["/robots.txt", "/admin/"]})
    
    # 3. Generate Report
    generator = HTMLGenerator()
    try:
        output = generator.generate(collector.get_context(), "test_report.html")
        print(f"Report generated successfully at: {output}")
        
        # Verify file exists
        if os.path.exists(output):
            print("File verified on disk.")
            with open(output, 'r') as f:
                content = f.read()
                if "SQL Injection" in content and "example.com" in content:
                    print("Content verification passed.")
                else:
                    print("Content verification FAILED.")
        else:
            print("File not found.")
            
    except Exception as e:
        print(f"Generation failed: {e}")

if __name__ == "__main__":
    test_reporting()
