"""
URLReporter: Generates individual reports per URL with DAST/SAST analysis and vulnerabilities.

Creates structured folders with:
- Analysis report (DAST/SAST combined)
- Vulnerabilities found and VALIDATED
- Screenshots for XSS VALIDATION (capturing popup/alert - the ONLY way to prove XSS)
- Metadata and logs

IMPORTANT: Screenshots are NOT decorative evidence. They are CRITICAL for XSS validation.
The only way to confirm XSS execution is to capture the alert popup in the browser.

Author: BugtraceAI-CLI Team
"""
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import hashlib

from bugtrace.utils.logger import get_logger

logger = get_logger("reporting.url_reporter")


class URLReporter:
    """Generates individual reports for each analyzed URL."""
    
    def __init__(self, base_report_dir: str):
        """
        Initialize URL Reporter.
        
        Args:
            base_report_dir: Base directory for all reports (e.g., reports/target_timestamp/)
        """
        self.base_report_dir = Path(base_report_dir)
        self.url_reports_dir = self.base_report_dir / "url_reports"
        self.url_reports_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"📁 URLReporter initialized: {self.url_reports_dir}")
    
    def _generate_url_folder_name(self, url: str) -> str:
        """
        Generate a clean folder name from URL.
        
        Args:
            url: Target URL
            
        Returns:
            Clean folder name (hash-based to avoid filesystem issues)
        """
        parsed = urlparse(url)
        
        # Create a readable prefix from path
        path_parts = [p for p in parsed.path.split('/') if p]
        if path_parts:
            prefix = '_'.join(path_parts[:2])  # Take first 2 path segments
        else:
            prefix = "root"
        
        # Clean prefix (remove special characters)
        prefix = ''.join(c if c.isalnum() or c == '_' else '_' for c in prefix)
        prefix = prefix[:30]  # Limit length
        
        # Generate hash for uniqueness
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        return f"{prefix}_{url_hash}"
    
    def create_url_report(
        self,
        url: str,
        analysis_results: Dict,
        vulnerabilities: List[Dict],
        screenshots: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ) -> Path:
        """
        Create a complete report for a single URL.
        
        Args:
            url: Target URL
            analysis_results: DAST/SAST analysis results
            vulnerabilities: List of vulnerabilities found
            screenshots: Paths to screenshot files (XSS VALIDATION ONLY - captures of popup/alert)
            metadata: Additional metadata (params, tech stack, etc.)
            
        Returns:
            Path to the created report directory
        """
        # Create URL-specific folder
        folder_name = self._generate_url_folder_name(url)
        url_dir = self.url_reports_dir / folder_name
        url_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"📝 Creating report for URL: {url} -> {folder_name}")
        
        # Create subdirectories
        screenshots_dir = url_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)
        
        # 1. Save analysis report (DAST/SAST combined)
        self._save_analysis_report(url_dir, url, analysis_results, metadata)
        
        # 2. Save vulnerabilities report
        self._save_vulnerabilities_report(url_dir, url, vulnerabilities)
        
        # 3. Copy XSS validation screenshots (alert popup captures)
        if screenshots:
            self._handle_screenshots(screenshots_dir, screenshots)
        
        # 4. Save metadata
        self._save_metadata(url_dir, url, metadata)
        
        # 5. Create summary index
        self._create_summary_index(url_dir, url, analysis_results, vulnerabilities)
        
        logger.info(f"✅ Report created: {url_dir}")
        return url_dir
    
    def _save_analysis_report(
        self,
        url_dir: Path,
        url: str,
        analysis_results: Dict,
        metadata: Optional[Dict]
    ):
        """Save DAST/SAST combined analysis report."""
        report_path = url_dir / "analysis_dast_sast.md"

        with open(report_path, 'w', encoding='utf-8') as f:
            self._write_report_header(f, url)
            self._write_metadata_section(f, metadata)
            self._write_dast_section(f, analysis_results)
            self._write_sast_section(f, analysis_results)
            self._write_risk_assessment(f, analysis_results)

        logger.debug(f"Saved analysis report: {report_path}")

    def _write_report_header(self, f, url: str):
        """Write report header with URL and timestamp."""
        f.write(f"# URL Analysis Report - DAST/SAST\n\n")
        f.write(f"**Target URL:** `{url}`\n\n")
        f.write(f"**Timestamp:** {datetime.now().isoformat()}\n\n")
        f.write("---\n\n")

    def _write_metadata_section(self, f, metadata: Optional[Dict]):
        """Write metadata section if available."""
        if not metadata:
            return

        f.write("## 🔍 Metadata\n\n")
        if 'params' in metadata:
            f.write(f"**Parameters:** {', '.join(metadata['params'].keys())}\n\n")
        if 'tech_stack' in metadata:
            f.write(f"**Technology Stack:** {', '.join(metadata['tech_stack'])}\n\n")
        if 'response_time' in metadata:
            f.write(f"**Response Time:** {metadata['response_time']}ms\n\n")
        f.write("\n")

    def _write_dast_section(self, f, analysis_results: Dict):
        """Write DAST analysis section."""
        f.write("## 🎯 DAST Analysis (Dynamic Testing)\n\n")
        if 'dast' not in analysis_results:
            f.write("*No DAST analysis performed*\n\n")
            return

        dast = analysis_results['dast']
        f.write(f"**Status:** {dast.get('status', 'N/A')}\n\n")
        f.write(f"**Confidence:** {dast.get('confidence', 0)}%\n\n")

        if 'findings' in dast:
            f.write("### Findings:\n\n")
            for finding in dast['findings']:
                f.write(f"- **{finding.get('type', 'Unknown')}**: {finding.get('description', '')}\n")
        f.write("\n")

    def _write_sast_section(self, f, analysis_results: Dict):
        """Write SAST analysis section."""
        f.write("## 📊 SAST Analysis (Static Code Analysis)\n\n")
        if 'sast' not in analysis_results:
            f.write("*No SAST analysis performed*\n\n")
            return

        sast = analysis_results['sast']
        f.write(f"**Patterns Detected:** {len(sast.get('patterns', []))}\n\n")

        if 'patterns' in sast:
            f.write("### Vulnerable Patterns:\n\n")
            for pattern in sast['patterns']:
                f.write(f"- **{pattern.get('name', 'Unknown')}**\n")
                f.write(f"  - **Risk:** {pattern.get('risk_level', 'Unknown')}\n")
                f.write(f"  - **Details:** {pattern.get('details', '')}\n\n")

    def _write_risk_assessment(self, f, analysis_results: Dict):
        """Write overall risk assessment section."""
        f.write("## ⚠️ Risk Assessment\n\n")
        overall_risk = analysis_results.get('overall_risk', 'Unknown')
        f.write(f"**Overall Risk Level:** {overall_risk}\n\n")

        if 'recommendations' in analysis_results:
            f.write("### Recommendations:\n\n")
            for rec in analysis_results['recommendations']:
                f.write(f"- {rec}\n")
    
    def _save_vulnerabilities_report(
        self,
        url_dir: Path,
        url: str,
        vulnerabilities: List[Dict]
    ):
        """Save vulnerabilities report."""
        # JSON format for machine-readable
        self._save_vulnerabilities_json(url_dir, url, vulnerabilities)

        # Markdown format for human-readable
        md_path = url_dir / "vulnerabilities.md"
        self._save_vulnerabilities_markdown(md_path, url, vulnerabilities)

        logger.debug(f"Saved vulnerabilities report: {md_path}")

    def _save_vulnerabilities_json(self, url_dir: Path, url: str, vulnerabilities: List[Dict]):
        """Save JSON format vulnerability report."""
        json_path = url_dir / "vulnerabilities.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }, f, indent=2)

    def _save_vulnerabilities_markdown(self, md_path: Path, url: str, vulnerabilities: List[Dict]):
        """Save markdown format vulnerability report."""
        with open(md_path, 'w', encoding='utf-8') as f:
            self._write_vuln_report_header(f, url, vulnerabilities)

            if not vulnerabilities:
                f.write("✅ **No vulnerabilities found**\n")
            else:
                self._write_vulnerabilities_by_severity(f, vulnerabilities)

    def _write_vuln_report_header(self, f, url: str, vulnerabilities: List[Dict]):
        """Write vulnerability report header."""
        f.write(f"# Vulnerabilities Report\n\n")
        f.write(f"**Target URL:** `{url}`\n\n")
        f.write(f"**Total Vulnerabilities:** {len(vulnerabilities)}\n\n")
        f.write("---\n\n")

    def _write_vulnerabilities_by_severity(self, f, vulnerabilities: List[Dict]):
        """Write vulnerabilities grouped by severity."""
        by_severity = self._group_by_severity(vulnerabilities)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
            vulns = by_severity.get(severity, [])
            if vulns:
                self._write_severity_section(f, severity, vulns)

    def _write_severity_section(self, f, severity: str, vulns: List[Dict]):
        """Write a severity-level section with all vulnerabilities."""
        emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFORMATIONAL': 'ℹ️'
        }.get(severity, '⚪')

        f.write(f"## {emoji} {severity} ({len(vulns)})\n\n")

        for idx, vuln in enumerate(vulns, 1):
            self._write_single_vulnerability(f, vuln, idx)

    def _write_single_vulnerability(self, f, vuln: Dict, idx: int):
        """Write a single vulnerability entry."""
        f.write(f"### {idx}. {vuln.get('type', 'Unknown Vulnerability')}\n\n")
        f.write(f"**Parameter:** `{vuln.get('parameter', 'N/A')}`\n\n")
        f.write(f"**Confidence:** {vuln.get('confidence', 0)}%\n\n")

        if 'payload' in vuln:
            f.write(f"**Payload:**\n```\n{vuln['payload']}\n```\n\n")

        if 'details' in vuln:
            f.write(f"**Details:** {vuln['details']}\n\n")

        # Write vulnerability-specific deep dives
        self._write_vuln_deep_dive(f, vuln)

        # Validation status
        self._write_validation_status(f, vuln)

        f.write("---\n\n")

    def _write_vuln_deep_dive(self, f, vuln: Dict):
        """Write vulnerability-specific deep dive sections."""
        # CSTI Reporting
        if vuln.get('type') == 'CSTI' or 'template' in vuln.get('type', '').lower():
            self._write_csti_deep_dive(f, vuln)

        # SQLi Reporting
        vuln_type = vuln.get('type', '').upper()
        if vuln.get('injection_type') and (vuln_type == 'SQLI' or 'SQL' in vuln_type):
            self._write_sqli_deep_dive(f, vuln)

        # XSS Reporting
        if 'xss_type' in vuln:
            self._write_xss_deep_dive(f, vuln)

    def _write_csti_deep_dive(self, f, vuln: Dict):
        """Write CSTI-specific details."""
        meta = vuln.get('csti_metadata', {})
        f.write(f"#### 🎭 CSTI Deep Dive\n\n")
        f.write(f"- **Engine:** {meta.get('engine', 'Unknown')} ({meta.get('type', 'Unknown')})\n")
        f.write(f"- **Syntax:** `{meta.get('syntax', 'Unknown')}`\n")
        f.write(f"- **Confirmed URL:** `{meta.get('verified_url', vuln.get('url'))}`\n")

        if meta.get('arithmetic_proof'):
            f.write(f"- **Proof:** Arithmetic evaluation confirmed (7*7 -> 49)\n")

        if vuln.get('reproduction_steps'):
            f.write(f"\n**🛠️ Reproduction:**\n")
            for step in vuln['reproduction_steps']:
                f.write(f"- {step}\n")
            f.write("\n")

        if vuln.get('reproduction'):
            f.write(f"**Command:**\n```bash\n{vuln['reproduction']}\n```\n\n")

    def _write_sqli_deep_dive(self, f, vuln: Dict):
        """Write SQLi-specific details."""
        f.write(f"#### 💉 SQLi Deep Dive\n\n")
        f.write(f"- **Technique:** {vuln.get('injection_type')}\n")
        f.write(f"- **DBMS:** {vuln.get('dbms_detected', 'Unknown')}\n")
        if vuln.get('columns_detected'):
            f.write(f"- **Columns Detected:** {vuln.get('columns_detected')}\n")

        if vuln.get('working_payload'):
            f.write(f"\n**🧨 Verification & Exploitation:**\n")
            f.write(f"**Working Payload:**\n```sql\n{vuln.get('working_payload')}\n```\n\n")

        if vuln.get('exploit_url_encoded'):
            f.write(f"**🔗 One-Click Exploit:**\n[{vuln.get('exploit_url')}]({vuln.get('exploit_url_encoded')})\n\n")

        self._write_sqli_extracted_data(f, vuln)
        self._write_sqli_reproduction(f, vuln)

    def _write_sqli_extracted_data(self, f, vuln: Dict):
        """Write SQLi extracted data section."""
        if vuln.get('extracted_databases') or vuln.get('extracted_tables'):
            f.write(f"**📂 Extracted Data (Proof):**\n")
            if vuln.get('extracted_databases'):
                f.write(f"- **Databases:** {', '.join(vuln['extracted_databases'])}\n")
            if vuln.get('extracted_tables'):
                f.write(f"- **Tables:** {', '.join(vuln['extracted_tables'])}\n")
            f.write("\n")

    def _write_sqli_reproduction(self, f, vuln: Dict):
        """Write SQLi reproduction commands."""
        if vuln.get('reproduction_steps'):
            f.write(f"**🛠️ Reproduction:**\n")
            for step in vuln['reproduction_steps']:
                f.write(f"- {step}\n")
            f.write("\n")

        if vuln.get('curl_command'):
            f.write(f"**cURL:**\n```bash\n{vuln['curl_command']}\n```\n")

        if vuln.get('sqlmap_reproduce_command'):
            f.write(f"**SQLMap:**\n```bash\n{vuln['sqlmap_reproduce_command']}\n```\n")
        f.write("\n")

    def _write_xss_deep_dive(self, f, vuln: Dict):
        """Write XSS-specific details."""
        f.write(f"#### 🔬 XSS Deep Dive\n\n")
        f.write(f"- **Type:** {vuln.get('xss_type')}\n")
        f.write(f"- **Injection Context:** `{vuln.get('injection_context_type')}`\n")
        if vuln.get('vulnerable_code_snippet'):
            f.write(f"- **Snippet:** `{vuln.get('vulnerable_code_snippet')}`\n")
        f.write(f"- **Bypass Technique:** {vuln.get('escape_bypass_technique')} ({vuln.get('bypass_explanation')})\n\n")

        if vuln.get('exploit_url'):
            f.write(f"**🧨 Exploit URL (Click to Test):**\n[{vuln.get('exploit_url')}]({vuln.get('exploit_url_encoded')})\n\n")

        self._write_xss_verification(f, vuln)
        self._write_xss_reproduction_steps(f, vuln)

    def _write_xss_verification(self, f, vuln: Dict):
        """Write XSS verification methods."""
        if vuln.get('verification_methods'):
            f.write(f"**✅ HOW TO VERIFY (Avoid alerts):**\n")
            for vm in vuln['verification_methods']:
                f.write(f"- **{vm.get('name')}**: {vm.get('instructions')}\n")
                if vm.get('url_encoded'):
                    f.write(f"  - [👉 Execute Verification]({vm['url_encoded']})\n")
            f.write("\n")

    def _write_xss_reproduction_steps(self, f, vuln: Dict):
        """Write XSS reproduction steps."""
        if vuln.get('reproduction_steps'):
            f.write(f"**📝 Step-by-Step Reproduction:**\n")
            for step in vuln['reproduction_steps']:
                f.write(f"1. {step}\n")
            f.write("\n")

    def _write_validation_status(self, f, vuln: Dict):
        """Write validation status and screenshots."""
        vuln_type = vuln.get('type', '').upper()
        if 'validated' in vuln and vuln['validated']:
            if 'XSS' in vuln_type:
                f.write("✅ **XSS Validated** - Alert popup captured in browser\n\n")
            else:
                f.write("✅ **Validated** - Confirmed with technical evidence\n\n")

        if 'screenshot' in vuln:
            if 'XSS' in vuln_type:
                f.write(f"**XSS Validation Proof:** [Alert Screenshot](screenshots/{Path(vuln['screenshot']).name})\n\n")
            else:
                f.write(f"**Screenshot:** [View](screenshots/{Path(vuln['screenshot']).name})\n\n")
    
    def _group_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by severity."""
        grouped = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFORMATIONAL': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFORMATIONAL').upper()
            if severity in grouped:
                grouped[severity].append(vuln)
            else:
                grouped['INFORMATIONAL'].append(vuln)
        
        return grouped
    
    def _handle_screenshots(self, screenshots_dir: Path, screenshots: List[str]):
        """
        Copy screenshots to URL report directory.
        
        CRITICAL: These screenshots are for XSS VALIDATION ONLY.
        They capture the browser popup/alert to PROVE the XSS payload executed.
        This is the ONLY way to validate XSS vulnerabilities.
        """
        import shutil
        
        for screenshot_path in screenshots:
            if os.path.exists(screenshot_path):
                dest_path = screenshots_dir / Path(screenshot_path).name
                try:
                    shutil.copy2(screenshot_path, dest_path)
                    logger.debug(f"Copied XSS validation screenshot: {screenshot_path} -> {dest_path}")
                except Exception as e:
                    logger.error(f"Failed to copy screenshot {screenshot_path}: {e}")
    
    def _save_metadata(self, url_dir: Path, url: str, metadata: Optional[Dict]):
        """Save metadata as JSON."""
        if not metadata:
            metadata = {}
        
        metadata['url'] = url
        metadata['timestamp'] = datetime.now().isoformat()
        
        metadata_path = url_dir / "metadata.json"
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        
        logger.debug(f"Saved metadata: {metadata_path}")
    
    def _create_summary_index(
        self,
        url_dir: Path,
        url: str,
        analysis_results: Dict,
        vulnerabilities: List[Dict]
    ):
        """Create a quick summary index file."""
        index_path = url_dir / "README.md"
        
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(f"# Report for: {url}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            f.write("## 📋 Summary\n\n")
            f.write(f"- **Total Vulnerabilities:** {len(vulnerabilities)}\n")
            f.write(f"- **Overall Risk:** {analysis_results.get('overall_risk', 'Unknown')}\n")
            
            # Count by severity
            by_severity = self._group_by_severity(vulnerabilities)
            f.write(f"- **Critical:** {len(by_severity['CRITICAL'])}\n")
            f.write(f"- **High:** {len(by_severity['HIGH'])}\n")
            f.write(f"- **Medium:** {len(by_severity['MEDIUM'])}\n")
            f.write(f"- **Low:** {len(by_severity['LOW'])}\n\n")
            
            f.write("## 📁 Report Files\n\n")
            f.write("- [`analysis_dast_sast.md`](analysis_dast_sast.md) - Combined DAST/SAST analysis\n")
            f.write("- [`vulnerabilities.md`](vulnerabilities.md) - Detailed vulnerabilities report\n")
            f.write("- [`vulnerabilities.json`](vulnerabilities.json) - Machine-readable format\n")
            f.write("- [`metadata.json`](metadata.json) - Technical metadata\n")
            f.write("- [`screenshots/`](screenshots/) - XSS validation (alert popup captures)\n")
        
        logger.debug(f"Created summary index: {index_path}")
    
    def generate_master_index(self) -> Path:
        """Generate master index of all URL reports."""
        index_path = self.url_reports_dir / "INDEX.md"
        
        # Collect all URL reports
        url_dirs = [d for d in self.url_reports_dir.iterdir() if d.is_dir()]
        
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write("# URL Reports Index\n\n")
            f.write(f"**Total URLs Analyzed:** {len(url_dirs)}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            f.write("## 📊 Reports by URL\n\n")
            
            for url_dir in sorted(url_dirs, key=lambda x: x.name):
                # Read metadata to get original URL
                metadata_file = url_dir / "metadata.json"
                if metadata_file.exists():
                    with open(metadata_file, 'r') as mf:
                        metadata = json.load(mf)
                        url = metadata.get('url', 'Unknown')
                else:
                    url = url_dir.name
                
                # Read summary stats
                vulns_file = url_dir / "vulnerabilities.json"
                vuln_count = 0
                if vulns_file.exists():
                    with open(vulns_file, 'r') as vf:
                        vulns_data = json.load(vf)
                        vuln_count = vulns_data.get('total_vulnerabilities', 0)
                
                status_emoji = "🔴" if vuln_count > 0 else "✅"
                f.write(f"### {status_emoji} [{url}]({url_dir.name}/README.md)\n\n")
                f.write(f"- **Folder:** `{url_dir.name}`\n")
                f.write(f"- **Vulnerabilities:** {vuln_count}\n\n")
        
        logger.info(f"✅ Master index created: {index_path}")
        return index_path
