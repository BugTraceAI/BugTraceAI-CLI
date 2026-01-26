#!/usr/bin/env python3
"""
Report Quality Evaluation Script

This script evaluates the quality of generated reports according to the
metrics defined in report_quality_evaluation.md.

Usage:
    python scripts/evaluate_report_quality.py [report_dir]
    
If no report_dir is provided, it will evaluate the most recent report.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class EvaluationResult:
    """Stores evaluation results for a single check."""
    name: str
    passed: bool
    details: str = ""
    level: str = "CRITICAL"  # CRITICAL, IMPORTANT, NICE
    
@dataclass
class ReportEvaluation:
    """Complete evaluation of a report."""
    report_dir: Path
    checks: List[EvaluationResult] = field(default_factory=list)
    findings_count: int = 0
    true_positives: int = 0
    false_positives: int = 0
    
    @property
    def fp_rate(self) -> float:
        if self.findings_count == 0:
            return 0.0
        return (self.false_positives / self.findings_count) * 100
    
    @property
    def critical_passed(self) -> int:
        return sum(1 for c in self.checks if c.level == "CRITICAL" and c.passed)
    
    @property
    def critical_total(self) -> int:
        return sum(1 for c in self.checks if c.level == "CRITICAL")
    
    @property
    def overall_score(self) -> float:
        if not self.checks:
            return 0.0
        weights = {"CRITICAL": 3, "IMPORTANT": 2, "NICE": 1}
        total_weight = sum(weights.get(c.level, 1) for c in self.checks)
        weighted_score = sum(weights.get(c.level, 1) for c in self.checks if c.passed)
        return (weighted_score / total_weight) * 100


class ReportQualityEvaluator:
    """Evaluates report quality based on report_quality_evaluation.md criteria."""
    
    # Known vulnerabilities for test targets (ground truth)
    KNOWN_VULNS = {
        "testphp.vulnweb.com": {
            "true_positives": [
                {"type": "SQL Injection", "url": "/listproducts.php", "param": "cat"},
                {"type": "SQL Injection", "url": "/artists.php", "param": "artist"},
                {"type": "XSS", "url": "/search.php", "param": "test"},
            ],
            "false_positive_indicators": [
                "WAF block",
                "403 Forbidden",
                "429 Too Many Requests",
                "CAPTCHA",
                "Rate limit",
            ]
        },
        "ginandjuice.shop": {
            "true_positives": [
                {"type": "DOM XSS", "url": "/search", "param": "hash"},
                {"type": "SQL Injection", "url": "/product", "param": "category"},
            ],
            "false_positive_indicators": [
                "WAF block",
                "CAPTCHA",
                "Rate limit",
                "Generic error",
                "Potential only",
            ]
        }
    }
    
    def __init__(self, report_dir: Path):
        self.report_dir = Path(report_dir)
        self.evaluation = ReportEvaluation(report_dir=self.report_dir)
        
    def evaluate(self) -> ReportEvaluation:
        """Run all evaluation checks."""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}📊 REPORT QUALITY EVALUATION{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"📁 Report: {self.report_dir.name}\n")
        
        # Level 1: CRITICAL checks
        self._check_report_exists()
        self._check_html_valid()
        self._check_findings_exist()
        self._check_evidence_present()
        
        # Level 2: IMPORTANT checks
        self._check_professional_formatting()
        self._check_finding_details()
        self._check_summary_stats()
        
        # Level 3: NICE TO HAVE
        self._check_advanced_features()
        self._check_metadata()
        
        # False Positive Analysis
        self._analyze_false_positives()
        
        return self.evaluation
    
    def _add_check(self, name: str, passed: bool, details: str = "", level: str = "CRITICAL"):
        """Add a check result."""
        result = EvaluationResult(name=name, passed=passed, details=details, level=level)
        self.evaluation.checks.append(result)
        
        icon = "✅" if passed else "❌"
        color = Colors.GREEN if passed else Colors.FAIL
        level_color = {
            "CRITICAL": Colors.FAIL,
            "IMPORTANT": Colors.WARNING,
            "NICE": Colors.CYAN
        }.get(level, Colors.ENDC)
        
        print(f"  {icon} [{level_color}{level}{Colors.ENDC}] {name}")
        if details and not passed:
            print(f"      └─ {Colors.WARNING}{details}{Colors.ENDC}")
    
    # ========== LEVEL 1: CRITICAL CHECKS ==========
    
    def _check_report_exists(self):
        """Check if report folder and main files exist."""
        print(f"\n{Colors.BOLD}Level 1: CRITICAL CHECKS{Colors.ENDC}")
        
        # Check folder exists
        exists = self.report_dir.exists() and self.report_dir.is_dir()
        self._add_check("Report folder exists", exists, 
                       f"Expected folder at {self.report_dir}" if not exists else "")
        
        # Check report.html exists
        html_path = self.report_dir / "report.html"
        if not html_path.exists():
            html_path = self.report_dir / "REPORT.html"
        html_exists = html_path.exists()
        self._add_check("report.html exists", html_exists,
                       "Main HTML report file not found" if not html_exists else "")
        
        # Check file size (should be > 10KB as per doc)
        if html_exists:
            size_kb = html_path.stat().st_size / 1024
            size_ok = size_kb > 10
            self._add_check("HTML file size > 10KB", size_ok,
                           f"Size is {size_kb:.1f}KB, expected > 10KB" if not size_ok else "")
    
    def _check_html_valid(self):
        """Check if HTML renders correctly."""
        html_path = self.report_dir / "report.html"
        if not html_path.exists():
            html_path = self.report_dir / "REPORT.html"
        
        if not html_path.exists():
            self._add_check("HTML renders correctly", False, "HTML file not found")
            return
        
        try:
            content = html_path.read_text(encoding='utf-8')
            # Basic structure checks
            has_doctype = "<!DOCTYPE" in content.upper() or "<!doctype" in content
            has_html_tag = "<html" in content.lower()
            has_body = "<body" in content.lower()
            has_head = "<head" in content.lower()
            
            valid = has_doctype and has_html_tag and has_body and has_head
            details = ""
            if not valid:
                missing = []
                if not has_doctype: missing.append("DOCTYPE")
                if not has_html_tag: missing.append("<html>")
                if not has_body: missing.append("<body>")
                if not has_head: missing.append("<head>")
                details = f"Missing: {', '.join(missing)}"
            
            self._add_check("HTML structure valid", valid, details)
        except Exception as e:
            self._add_check("HTML renders correctly", False, str(e))
    
    def _check_findings_exist(self):
        """Check if all findings are properly listed."""
        json_path = self.report_dir / "engagement_data.json"
        
        if not json_path.exists():
            self._add_check("Findings documented", False, "engagement_data.json not found")
            return
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            findings = data.get("findings", [])
            self.evaluation.findings_count = len(findings)
            
            # Filter vulnerabilities only (not recon data)
            vulns = [f for f in findings if f.get("type") == "vulnerability"]
            
            has_findings = len(vulns) > 0
            self._add_check("Findings documented", has_findings,
                           f"Found {len(vulns)} vulnerabilities" if has_findings else "No vulnerabilities found")
        except Exception as e:
            self._add_check("Findings documented", False, str(e))
    
    def _check_evidence_present(self):
        """Check if findings have proper evidence."""
        json_path = self.report_dir / "engagement_data.json"
        captures_dir = self.report_dir / "captures"
        evidence_dir = self.report_dir / "evidence"
        
        if not json_path.exists():
            return
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            findings = [f for f in data.get("findings", []) if f.get("type") == "vulnerability"]
            
            # Check XSS findings have screenshots
            # Only VALIDATED XSS findings require screenshots - potential ones are hypotheses
            xss_findings = [f for f in findings if "XSS" in f.get("title", "").upper() or 
                          "XSS" in f.get("metadata", {}).get("type", "").upper()]
            
            # Separate validated vs potential XSS
            validated_xss = [f for f in xss_findings if f.get("validated") == True]
            potential_xss = [f for f in xss_findings if f.get("validated") != True]
            
            validated_xss_with_screenshots = sum(1 for f in validated_xss if f.get("screenshot_path"))
            
            if validated_xss:
                xss_evidence = validated_xss_with_screenshots == len(validated_xss)
                self._add_check("XSS findings have screenshots", xss_evidence,
                               f"{validated_xss_with_screenshots}/{len(validated_xss)} validated XSS findings have screenshots")
            elif potential_xss:
                # No validated XSS, only potential - this is acceptable (they're hypotheses)
                self._add_check("XSS findings have screenshots", True,
                               f"0 validated XSS (only {len(potential_xss)} potential)")
            
            # Check SQLi findings have error messages
            sqli_findings = [f for f in findings if "SQL" in f.get("title", "").upper() or 
                           "SQL" in f.get("metadata", {}).get("type", "").upper()]
            sqli_with_evidence = sum(1 for f in sqli_findings 
                                    if f.get("evidence") or 
                                    f.get("metadata", {}).get("reproduction"))
            
            if sqli_findings:
                sqli_evidence = sqli_with_evidence == len(sqli_findings)
                self._add_check("SQLi findings have evidence", sqli_evidence,
                               f"{sqli_with_evidence}/{len(sqli_findings)} SQLi findings have reproduction commands")
            
            # Check captures directory has files
            has_captures = False
            if captures_dir.exists():
                captures = list(captures_dir.glob("*"))
                has_captures = len(captures) > 0
            if evidence_dir.exists():
                evidence = list(evidence_dir.glob("*"))
                has_captures = has_captures or len(evidence) > 0
            
            self._add_check("Evidence directory has files", has_captures,
                           "No files in captures/ or evidence/ directory")
                           
        except Exception as e:
            self._add_check("Evidence present", False, str(e))
    
    # ========== LEVEL 2: IMPORTANT CHECKS ==========
    
    def _check_professional_formatting(self):
        """Check professional presentation."""
        print(f"\n{Colors.BOLD}Level 2: IMPORTANT CHECKS{Colors.ENDC}")
        
        html_path = self.report_dir / "report.html"
        if not html_path.exists():
            html_path = self.report_dir / "REPORT.html"
        
        if not html_path.exists():
            return
        
        content = html_path.read_text(encoding='utf-8').lower()
        
        # Check for styling
        has_css = "<style" in content or "stylesheet" in content
        self._add_check("Professional styling", has_css, 
                       "No CSS styling found", level="IMPORTANT")
        
        # Check for severity color coding
        severity_indicators = ["critical", "high", "medium", "low"]
        has_severity_colors = all(s in content for s in severity_indicators)
        self._add_check("Severity color coding", has_severity_colors,
                       "Missing severity levels in report", level="IMPORTANT")
        
        # Check for navigation/TOC
        has_nav = "navigation" in content or "sidebar" in content or "nav" in content
        self._add_check("Navigation/TOC present", has_nav,
                       "No navigation elements found", level="IMPORTANT")
    
    def _check_finding_details(self):
        """Check if findings have complete details."""
        json_path = self.report_dir / "engagement_data.json"
        
        if not json_path.exists():
            return
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            findings = [f for f in data.get("findings", []) if f.get("type") == "vulnerability"]
            
            if not findings:
                return
            
            # Check for URL in each finding
            findings_with_url = sum(1 for f in findings if f.get("metadata", {}).get("url"))
            has_urls = findings_with_url == len(findings)
            self._add_check("Findings have URLs", has_urls,
                           f"{findings_with_url}/{len(findings)} have URLs", level="IMPORTANT")
            
            # Check for parameters
            findings_with_param = sum(1 for f in findings if f.get("metadata", {}).get("parameter"))
            has_params = findings_with_param == len(findings)
            self._add_check("Findings have parameters", has_params,
                           f"{findings_with_param}/{len(findings)} have parameters", level="IMPORTANT")
            
            # Check for payloads
            findings_with_payload = sum(1 for f in findings if 
                                       f.get("metadata", {}).get("payload") or
                                       any(e.get("content") for e in f.get("evidence", [])))
            has_payloads = findings_with_payload == len(findings)
            self._add_check("Findings have payloads", has_payloads,
                           f"{findings_with_payload}/{len(findings)} have payloads", level="IMPORTANT")
                           
        except Exception as e:
            pass
    
    def _check_summary_stats(self):
        """Check summary statistics."""
        json_path = self.report_dir / "engagement_data.json"
        
        if not json_path.exists():
            return
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            stats = data.get("stats", {})
            
            has_duration = stats.get("duration_seconds") is not None
            self._add_check("Scan duration recorded", has_duration, level="IMPORTANT")
            
            has_urls_scanned = stats.get("urls_scanned") is not None
            self._add_check("URLs scanned count", has_urls_scanned, level="IMPORTANT")
            
        except Exception as e:
            pass
    
    # ========== LEVEL 3: NICE TO HAVE ==========
    
    def _check_advanced_features(self):
        """Check advanced report features."""
        print(f"\n{Colors.BOLD}Level 3: NICE TO HAVE{Colors.ENDC}")
        
        html_path = self.report_dir / "report.html"
        if not html_path.exists():
            html_path = self.report_dir / "REPORT.html"
        
        if html_path.exists():
            content = html_path.read_text(encoding='utf-8').lower()
            
            # Check for embedded images
            has_images = "<img" in content
            self._add_check("Screenshots embedded", has_images, level="NICE")
            
            # Check for syntax highlighting
            has_code = "<code" in content or "<pre" in content
            self._add_check("Code syntax highlighting", has_code, level="NICE")
            
            # Check for chart
            has_chart = "chart" in content or "canvas" in content
            self._add_check("Risk chart present", has_chart, level="NICE")
    
    def _check_metadata(self):
        """Check metadata completeness."""
        json_path = self.report_dir / "engagement_data.json"
        
        if not json_path.exists():
            return
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            has_timestamp = data.get("scan_date") is not None
            self._add_check("Scan timestamp", has_timestamp, level="NICE")
            
            has_version = data.get("tool_version") is not None
            self._add_check("Tool version", has_version, level="NICE")
            
        except Exception as e:
            pass
    
    # ========== FALSE POSITIVE ANALYSIS ==========
    
    def _analyze_false_positives(self):
        """Analyze findings for false positives."""
        print(f"\n{Colors.BOLD}FALSE POSITIVE ANALYSIS{Colors.ENDC}")
        
        json_path = self.report_dir / "engagement_data.json"
        
        if not json_path.exists():
            print(f"  ⚠️ Cannot analyze - engagement_data.json not found")
            return
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            findings = [f for f in data.get("findings", []) if f.get("type") == "vulnerability"]
            
            # Check for potential false positive indicators
            fp_indicators = [
                "potential",
                "possible",
                "unverified",
                "theoretical",
                "may be",
                "might be",
                "could be",
            ]
            
            potential_fps = []
            validated = []
            
            for finding in findings:
                # The validated field is the source of truth
                if finding.get("validated") == True:
                    validated.append(finding)
                else:
                    # Not validated - considered potential FP
                    potential_fps.append(finding)
            
            self.evaluation.true_positives = len(validated)
            self.evaluation.false_positives = len(potential_fps)
            
            # Calculate FP rate based on total vulnerabilities
            fp_rate = (len(potential_fps) / len(findings) * 100) if findings else 0.0
            
            print(f"\n  📊 Findings Analysis:")
            print(f"      Total Findings: {len(findings)}")
            print(f"      Validated (TP): {len(validated)}")
            print(f"      Potential FPs:  {len(potential_fps)}")
            print(f"      FP Rate:        {fp_rate:.1f}% (target: <5%)")
            
            if potential_fps:
                print(f"\n  ⚠️ Potential False Positives:")
                for fp in potential_fps[:5]:  # Show first 5
                    title = fp.get("title", "Unknown")[:50]
                    print(f"      - {title}")
                if len(potential_fps) > 5:
                    print(f"      ... and {len(potential_fps) - 5} more")
                    
        except Exception as e:
            print(f"  ❌ Analysis failed: {e}")
    
    def print_summary(self):
        """Print evaluation summary."""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}📋 EVALUATION SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        # Calculate scores
        critical_passed = self.evaluation.critical_passed
        critical_total = self.evaluation.critical_total
        overall_score = self.evaluation.overall_score
        
        # Determine overall status
        if critical_passed == critical_total and overall_score >= 80:
            status = f"{Colors.GREEN}✅ PASS{Colors.ENDC}"
            status_text = "Ready for production"
        elif critical_passed >= critical_total * 0.8:
            status = f"{Colors.WARNING}⚠️ CONDITIONAL{Colors.ENDC}"
            status_text = "Minor issues to address"
        else:
            status = f"{Colors.FAIL}❌ FAIL{Colors.ENDC}"
            status_text = "Major issues require attention"
        
        print(f"\n  Overall Status: {status}")
        print(f"  Assessment:     {status_text}")
        print(f"\n  Scores:")
        print(f"      Critical Checks: {critical_passed}/{critical_total} passed")
        print(f"      Overall Score:   {overall_score:.1f}%")
        print(f"      FP Rate:         {self.evaluation.fp_rate:.1f}% (target: <5%)")
        
        # List failed checks
        failed_checks = [c for c in self.evaluation.checks if not c.passed]
        if failed_checks:
            print(f"\n  {Colors.WARNING}Issues to Address:{Colors.ENDC}")
            for check in failed_checks:
                print(f"      - [{check.level}] {check.name}")
                if check.details:
                    print(f"        {check.details}")
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        
        return self.evaluation


def find_latest_report(reports_dir: Path) -> Optional[Path]:
    """Find the most recent report directory."""
    if not reports_dir.exists():
        return None
    
    report_dirs = [d for d in reports_dir.iterdir() if d.is_dir() and d.name != ".gitkeep"]
    if not report_dirs:
        return None
    
    # Sort by modification time
    report_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return report_dirs[0]


def main():
    """Main entry point."""
    reports_base = Path(__file__).parent.parent / "reports"
    
    if len(sys.argv) > 1:
        report_dir = Path(sys.argv[1])
    else:
        report_dir = find_latest_report(reports_base)
    
    if not report_dir or not report_dir.exists():
        print(f"❌ No report found to evaluate")
        print(f"   Usage: python {sys.argv[0]} [report_directory]")
        sys.exit(1)
    
    evaluator = ReportQualityEvaluator(report_dir)
    evaluation = evaluator.evaluate()
    evaluator.print_summary()
    
    # Exit with appropriate code
    if evaluation.critical_passed < evaluation.critical_total:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
