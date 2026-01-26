
import sys
import glob
import os
from bugtrace.reporting.collector import DataCollector
from bugtrace.reporting.markdown_generator import MarkdownGenerator
from bugtrace.reporting.generator import HTMLGenerator  # Ensure HTML is also updated if needed

def regenerate_report():
    print("🚀 Regenerating Last Report with Triager-Ready Format...")

    # 1. Find the latest validated engagement data in the reports folder
    # We look for 'engagement_data.json' inside reports/final_validation subdirectories
    search_path = "reports/final_validation/*/engagement_data.json"
    files = glob.glob(search_path)
    
    if not files:
        print("❌ No existing validated reports found in reports/final_validation/")
        return

    # Sort by modification time to get the latest
    latest_file = max(files, key=os.path.getmtime)
    print(f"📄 Found latest engagement data: {latest_file}")

    # 2. Load context
    # DataCollector requires a target_url in init, but load_from_json will overwrite context
    collector = DataCollector("http://placeholder.url")
    collector.load_from_json(latest_file)
    context = collector.get_context()

    print(f"📊 Validated Findings: {len(context.findings)}")

    # 3. Generate New Markdown Report
    md_gen = MarkdownGenerator(output_base_dir="reports/final_validation")
    report_path = md_gen.generate(context)
    
    print(f"✅ Markdown Generated: {report_path}/technical_report.md")

    # 4. Generate New HTML Report
    html_gen = HTMLGenerator() # Default template dir
    # Construct output path for HTML
    # We want it in the same report directory
    report_name = os.path.basename(report_path) # e.g. report_...
    # But report_path from MarkdownGenerator is already the full folder path
    html_report_path = os.path.join(report_path, "report.html")
    
    html_gen.generate(context, html_report_path)
    
    print(f"✅ HTML Generated: {html_report_path}")

if __name__ == "__main__":
    regenerate_report()
