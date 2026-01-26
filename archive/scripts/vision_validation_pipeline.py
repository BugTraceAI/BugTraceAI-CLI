import asyncio
import os
import json
import glob
import shutil
from pathlib import Path
from datetime import datetime
from bugtrace.reporting.collector import DataCollector
from bugtrace.reporting.markdown_generator import MarkdownGenerator
from bugtrace.reporting.generator import HTMLGenerator
from bugtrace.agents.agentic_validator import AgenticValidator
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.core.config import settings

# Ensure logs dir exists
os.makedirs("logs/screenshots", exist_ok=True)

async def capture_screenshot(url):
    from playwright.async_api import async_playwright
    import uuid
    path = os.path.abspath(f"logs/screenshots/{uuid.uuid4().hex[:8]}.png")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            print(f"    [Capture] Navigating to {url}")
            await page.goto(url, timeout=15000)
            await asyncio.sleep(2) # Wait for renders
            await page.screenshot(path=path)
            print(f"    [Capture] Screenshot saved to {path}")
        except Exception as e:
            print(f"    [Capture] Error: {e}")
            path = None
        await browser.close()
    return path

async def run_pipeline():
    target_url = "http://127.0.0.1:5150"
    
    # 1. Load Findings from State
    print("\n📂 PHASE 1: Loading findings from state...")
    findings = []
    for f in glob.glob('logs/state_*.json'):
        with open(f, 'r') as fd:
            data = json.load(fd)
            for find in data.get('findings', []):
                # Ensure we have common keys
                if 'url' not in find and 'target' in find:
                    find['url'] = find['target']
                findings.append(find)
    
    print(f"Found {len(findings)} findings to process.")

    # 2. Generate PRE-VALIDATION Report
    print("\n📝 PHASE 2: Generating Pre-Validation Report...")
    pre_collector = DataCollector(target_url)
    for f in findings: 
        pre_collector.add_vulnerability(f)
    
    md_gen = MarkdownGenerator(output_base_dir="reports/pre_validation")
    pre_report_dir = md_gen.generate(pre_collector.get_context())
    print(f"✅ Pre-Validation report directory created at: {pre_report_dir}")
    
    # 3. Launch Agentic Validator
    print("\n👁️ PHASE 3: Launching Agentic Validator (Vision-AI Review)...")
    validator = AgenticValidator()
    verifier = XSSVerifier(headless=True)
    
    validated_findings = []
    
    for i, find in enumerate(findings):
        vuln_type = str(find.get('type', '')).upper()
        url = find.get('url')
        payload = find.get('payload')
        
        print(f"[{i+1}/{len(findings)}] Reviewing: {vuln_type} on {url}")
        
        # Determine if we should attempt vision validation
        # We focus on high-impact visual ones: XSS, SQLi (errors), LFI (content), RCE (content)
        screenshot_path = None
        
        try:
            # SKIP LOGIC: Don't use Vision/Browser for Blind XSS or invisible attacks
            # SKIP LOGIC: Smart Selection of Validation Method
            is_blind = any(k in vuln_type for k in ['BLIND', 'HEADER', 'SSL', 'TLS', 'METHOD', 'STATUS'])
            if is_blind:
                print(f"  -> 🙈 Non-visual vulnerability ({vuln_type}). Skipping browser/vision.")
                screenshot_path = None
                find['validation_method'] = "Automated Request Analysis (No Browser)"
            elif 'XSS' in vuln_type and url:
                # XSS needs Browser (CDP/Playwright)
                print(f"  -> Tracing XSS execution in browser...")
                res = await verifier.verify_xss(url, screenshot_dir="logs/screenshots")
                screenshot_path = res.screenshot_path
                find['validation_method'] = "Browser Verification (CDP/Playwright)"
                if res.details.get('impact_data'):
                     find['metadata'] = find.get('metadata', {})
                     find['metadata']['impact_proof'] = res.details['impact_data']

            else:
                # Generic capture for Visual Vulnerabilities (SQLi Errors, RCE Output, Defacement)
                print(f"  -> Capturing page snapshot for Visual Validation...")
                screenshot_path = await capture_screenshot(url)
                find['validation_method'] = "Vision AI Analysis (Gemini)"
            
            if screenshot_path and os.path.exists(screenshot_path):
                print(f"  -> 🤖 Invoking Vision AI (Gemini) for human-like reasoning...")
                updated_find = await validator.validate_with_vision(find, screenshot_path)
                # Ensure screenshot path is in the finding metadata for the final report
                updated_find['screenshot_path'] = screenshot_path
                validated_findings.append(updated_find)
            else:
                print("  -> ⚠️ Skip Vision: No screenshot available.")
                validated_findings.append(find)
        except Exception as e:
            print(f"  -> ❌ Error during validation: {e}")
            validated_findings.append(find)

    # 4. Generate FINAL Reports
    print("\n📊 PHASE 4: Generating Final Validated Reports...")
    final_collector = DataCollector(target_url)
    for f in validated_findings: 
        final_collector.add_vulnerability(f)
    
    # Final MD with Vision Evidence
    final_md_gen = MarkdownGenerator(output_base_dir="reports/final_validation")
    final_report_dir = final_md_gen.generate(final_collector.get_context())
    print(f"✅ Final Technical Report generated at: {final_report_dir}")
    
    # Final HTML Report
    print("🎨 Rendering HTML Dashboard...")
    html_gen = HTMLGenerator()
    html_path = os.path.join(final_report_dir, "report.html")
    html_gen.generate(final_collector.get_context(), html_path)
    print(f"✅ Final HTML Report created: {html_path}")
    
    print("\n🚀 PIPELINE COMPLETE. All validated evidence is in reports/final_validation/")

if __name__ == "__main__":
    asyncio.run(run_pipeline())
