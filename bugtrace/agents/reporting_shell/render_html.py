"""Markdown/HTML/engagement render shell.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
from loguru import logger

from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client

from bugtrace.agents.base import BaseAgent
from bugtrace.core.database import get_db_manager
from bugtrace.core.event_bus import EventType, event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.json_parser import safe_json_loads, extract_json_list
from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln, get_remediation_for_vuln, get_reference_cve,
    normalize_severity, format_cve,
)
from bugtrace.reporting.poc_format import (
    build_query_url, curl_form_field, curl_get, curl_raw_body, curl_header,
    evidence_pairs, md_code_block, md_evidence_block, md_injection_point,
    md_labeled_block, md_document_with_values, md_step_with_block,
    md_step_with_value, plain_evidence_block, shell_word,
    template_expression_result, truncate_marked,
)
import hashlib
import math
import os
import shutil
import time


class ReportingRenderHtmlMixin:
    """ReportingRenderHtmlMixin."""

    @staticmethod
    def _get_js_component_policy(finding: Dict) -> Optional[Dict]:
        """Resolve a detected JS component through the scanner's advisory registry."""
        identifiers = " ".join(str(finding.get(key, "")) for key in (
            "parameter", "payload", "nuclei_template", "template_id"
        )).lower()
        match = re.search(r"js-vulnerable-([a-z0-9_-]+)", identifiers)
        if not match:
            return None

        from bugtrace.agents.nuclei.core import KNOWN_VULNERABLE_JS
        return KNOWN_VULNERABLE_JS.get(match.group(1))

    @staticmethod
    def _has_template_code_execution_proof(finding: Dict) -> bool:
        """Distinguish expression evaluation from demonstrated server-side execution."""
        if any(finding.get(flag) is True for flag in (
            "rce_confirmed", "code_execution_confirmed", "oob_confirmed"
        )):
            return True
        evidence = " ".join(str(finding.get(key, "")) for key in (
            "evidence", "http_response", "validator_notes", "execution_evidence"
        )).lower()
        return any(marker in evidence for marker in (
            "command output captured",
            "code execution confirmed",
            "file read confirmed",
            "oob callback received",
        ))

    def _generate_html_report(self, paths: Dict[str, Path]) -> Dict[str, Path]:
        """Generate HTML report using HTMLGenerator."""
        from bugtrace.reporting.generator import HTMLGenerator

        generator = HTMLGenerator()
        return {
            "report_html": Path(generator.generate(
                paths.get("engagement_data"),
                self.output_dir / "report.html"
            ))
        }

    def _copy_html_template(self) -> Path:
        """Copy the static HTML template that loads engagement_data.json.

        DEAD (verified 2026-07-28 by import graph): nothing calls this, nor the
        ``_create_minimal_html`` / ``_build_html_template`` pair below it. The report.html
        that ships is written by ``reporting/generator.py``, which copies
        ``templates/report_viewer.html`` — the viewer that HTML-ESCAPES every payload it
        prints. The two templates this method would use do NOT escape: they concatenate
        ``reproduction.poc`` / ``exploitation_details`` / ``validation.notes`` straight into
        ``innerHTML``, so any payload containing a tag would be swallowed by the parser and
        never shown. Revive either of them and that has to be fixed first.
        """
        # The HTML template location
        template_src = Path(__file__).parent.parent / "reporting" / "templates" / "report_dynamic.html"
        dest = self.output_dir / "report.html"

        if template_src.exists():
            shutil.copy(template_src, dest)
        else:
            # Create a minimal HTML if template doesn't exist
            self._create_minimal_html(dest)

        logger.info(f"[{self.name}] Copied report.html")
        return dest

    def _create_minimal_html(self, path: Path):
        """Create minimal HTML that loads JSON dynamically."""
        html = self._build_html_template()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html_template(self) -> str:
        """
        Build HTML template string for dynamic report viewer.
        Note: HTML template strings >50 lines are acceptable per 08-03 decision.
        """
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugTraceAI Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: system-ui, sans-serif; background: #f8fafc; }
        .severity-critical { background: #991b1b; color: white; }
        .severity-high { background: #dc2626; color: white; }
        .severity-medium { background: #d97706; color: white; }
        .severity-low { background: #2563eb; color: white; }
        .severity-info { background: #059669; color: white; }
        pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
    </style>
</head>
<body class="p-8">
    <div id="app" class="max-w-6xl mx-auto">
        <div class="text-center py-8">
            <p class="text-gray-500">Loading report...</p>
        </div>
    </div>

    <script>
        async function loadReport() {
            try {
                const response = await fetch('./engagement_data.json');
                const data = await response.json();
                renderReport(data);
            } catch (e) {
                document.getElementById('app').innerHTML =
                    '<p class="text-red-500">Error loading report: ' + e.message + '</p>';
            }
        }

        function renderReport(data) {
            const app = document.getElementById('app');

            let html = `
                <header class="mb-8">
                    <h1 class="text-3xl font-bold text-gray-900">Security Assessment Report</h1>
                    <p class="text-gray-600 mt-2">Target: ${data.meta.target}</p>
                    <p class="text-gray-500 text-sm">Scan ID: ${data.meta.scan_id} | Date: ${data.meta.scan_date}</p>
                </header>

                <section class="grid grid-cols-4 gap-4 mb-8">
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-green-600">${data.summary.validated}</p>
                        <p class="text-gray-600">Confirmed</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-yellow-600">${data.summary.manual_review}</p>
                        <p class="text-gray-600">Manual Review</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-red-600">${data.summary.false_positives}</p>
                        <p class="text-gray-600">False Positives</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-gray-600">${data.summary.total_findings}</p>
                        <p class="text-gray-600">Total</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-2xl font-bold mb-4">Confirmed Vulnerabilities</h2>
            `;

            if (data.findings.length === 0) {
                html += '<p class="text-gray-500">No confirmed vulnerabilities found.</p>';
            } else {
                data.findings.forEach((f, i) => {
                    const sevClass = 'severity-' + f.severity.toLowerCase();
                    html += `
                        <div class="bg-white rounded-lg shadow mb-4 overflow-hidden">
                            <div class="flex items-center justify-between p-4 border-b">
                                <h3 class="text-xl font-bold">${f.id}. ${f.type}</h3>
                                <span class="px-3 py-1 rounded text-sm font-bold ${sevClass}">${f.severity}</span>
                            </div>
                            <div class="p-4">
                                <p class="mb-2"><strong>URL:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.url}</code></p>
                                <p class="mb-2"><strong>Parameter:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.parameter}</code></p>
                                <p class="mb-4"><strong>Payload:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.payload}</code></p>
                                ${f.db_type ? `<p class="mb-2"><strong>DB Type:</strong> <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded">${f.db_type}</span></p>` : ''}
                                ${f.tamper_used ? `<p class="mb-2"><strong>Tamper Script:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.tamper_used}</code></p>` : ''}

                                <h4 class="font-bold mt-4 mb-2">Steps to Reproduce</h4>
                                <ol class="list-decimal list-inside mb-4">
                                    ${(f.reproduction && f.reproduction.steps) ? f.reproduction.steps.map(s => '<li>' + s + '</li>').join('') : '<li>No specific reproduction steps provided.</li>'}
                                </ol>

                                ${(f.reproduction && f.reproduction.poc && !f.reproduction.poc.trim().startsWith('#')) ?
                                `<h4 class="font-bold mt-4 mb-2">Proof of Concept</h4>
                                <pre class="whitespace-pre-wrap">${f.reproduction.poc}</pre>` : ''}

                                ${f.exploitation_details ? '<div class="mt-4 p-4 bg-red-50 border-l-4 border-red-500 rounded"><h4 class="font-bold text-red-700 mb-2">🎯 Exploitation Details</h4><pre class="whitespace-pre-wrap text-sm text-gray-800">' + f.exploitation_details + '</pre></div>' : ''}

                                ${f.validation.notes ? '<p class="mt-4 text-gray-600"><strong>Validator Notes:</strong> ' + f.validation.notes + '</p>' : ''}
                                ${f.validation.screenshot ? '<img src="' + f.validation.screenshot + '" class="mt-4 rounded border" />' : ''}
                            </div>
                        </div>
                    `;
                });
            }

            html += '</section>';
            app.innerHTML = html;
        }

        loadReport();
    </script>
</body>
</html>'''

