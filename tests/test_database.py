"""
Database layer tests for BugTraceAI.

Tests for:
- TASK-81: Race condition handling in get_or_create_target
- TASK-82: DetachedInstanceError prevention with expunge
- TASK-83: Enum usage for status fields
- TASK-85: Connection pooling
- TASK-87: Health check
- TASK-88: Metrics collection
- TASK-89: Backup functionality
"""
import os
import pytest
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from bugtrace.schemas.db_models import (
    TargetTable, ScanTable, FindingTable,
    ScanStatus, FindingStatus
)
from bugtrace.schemas.models import VulnType


class TestDatabaseManager:
    """Test suite for DatabaseManager class."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing."""
        from bugtrace.core.database import DatabaseManager

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            vector_path = os.path.join(tmpdir, "lancedb")
            db = DatabaseManager(
                db_url=f"sqlite:///{db_path}",
                vector_db_path=vector_path
            )
            yield db

    def test_get_or_create_target_basic(self, temp_db):
        """Test basic get_or_create_target functionality."""
        url = "https://example.com"

        # First call should create
        target1 = temp_db.get_or_create_target(url)
        assert target1 is not None
        assert target1.url == url
        assert target1.id is not None

        # Second call should return existing
        target2 = temp_db.get_or_create_target(url)
        assert target2.id == target1.id

    def test_get_or_create_target_race_condition(self, temp_db):
        """
        TASK-81: Test race condition handling with concurrent calls.

        Simulates multiple threads trying to create the same target simultaneously.
        Only one target should be created, and all threads should return the same target.
        """
        url = "https://race-test.example.com"
        results = []
        errors = []

        def create_target():
            try:
                target = temp_db.get_or_create_target(url)
                return target.id
            except Exception as e:
                errors.append(str(e))
                return None

        # Run 20 concurrent calls
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_target) for _ in range(20)]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

        # All should return the same target ID
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(set(results)) == 1, f"Multiple targets created: {set(results)}"

    def test_detached_instance_error_prevention(self, temp_db):
        """
        TASK-82: Test that findings can be accessed after session closes.

        The expunge pattern should prevent DetachedInstanceError when
        accessing finding attributes outside of the session context.
        """
        # Create target and scan
        target = temp_db.get_or_create_target("https://detach-test.example.com")

        # Create a scan
        with temp_db.get_session() as session:
            scan = ScanTable(
                target_id=target.id,
                status=ScanStatus.RUNNING,
                progress_percent=0
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

        # Save a finding
        temp_db.save_scan_result(
            target_url="https://detach-test.example.com",
            findings=[{
                "type": "XSS",
                "severity": "HIGH",
                "parameter": "test_param",
                "payload": "<script>alert(1)</script>",
                "confidence": 0.95
            }],
            scan_id=scan_id
        )

        # Get pending findings - these should be expunged
        findings = temp_db.get_pending_findings(scan_id=scan_id)

        # Access attributes after session is closed (should NOT raise DetachedInstanceError)
        assert len(findings) >= 1
        finding = findings[0]

        # These attribute accesses would raise DetachedInstanceError without expunge
        assert finding.type == VulnType.XSS
        assert finding.severity == "HIGH"
        assert finding.vuln_parameter == "test_param"
        assert finding.status == FindingStatus.PENDING_VALIDATION

    def test_findings_for_scan_expunge(self, temp_db):
        """Additional test for get_findings_for_scan expunge behavior."""
        target = temp_db.get_or_create_target("https://scan-test.example.com")

        with temp_db.get_session() as session:
            scan = ScanTable(
                target_id=target.id,
                status=ScanStatus.COMPLETED,
                progress_percent=100
            )
            session.add(scan)
            session.commit()
            scan_id = scan.id

        # Save multiple findings
        temp_db.save_scan_result(
            target_url="https://scan-test.example.com",
            findings=[
                {"type": "SQLI", "severity": "CRITICAL", "parameter": "id"},
                {"type": "XSS", "severity": "HIGH", "parameter": "name"},
            ],
            scan_id=scan_id
        )

        # Get findings for scan
        findings = temp_db.get_findings_for_scan(scan_id)

        # Access all findings outside session
        for f in findings:
            # These should work without DetachedInstanceError
            _ = f.type
            _ = f.severity
            _ = f.status

    def test_scan_status_enum(self, temp_db):
        """TASK-83: Test that ScanStatus enum is used correctly."""
        target = temp_db.get_or_create_target("https://enum-test.example.com")

        # Create scan with enum
        scan_id = temp_db.create_new_scan("https://enum-test.example.com")

        with temp_db.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            assert scan.status == ScanStatus.RUNNING

        # Update status with enum
        temp_db.update_scan_status(scan_id, ScanStatus.COMPLETED)

        with temp_db.get_session() as session:
            scan = session.get(ScanTable, scan_id)
            assert scan.status == ScanStatus.COMPLETED

    def test_finding_status_enum(self, temp_db):
        """TASK-83: Test that FindingStatus enum is used correctly."""
        target = temp_db.get_or_create_target("https://finding-enum-test.example.com")
        scan_id = temp_db.create_new_scan("https://finding-enum-test.example.com")

        temp_db.save_scan_result(
            target_url="https://finding-enum-test.example.com",
            findings=[{"type": "XSS", "severity": "HIGH", "parameter": "q"}],
            scan_id=scan_id
        )

        findings = temp_db.get_pending_findings(scan_id=scan_id)
        assert len(findings) >= 1

        finding = findings[0]
        assert finding.status == FindingStatus.PENDING_VALIDATION

        # Update finding status
        temp_db.update_finding_status(
            finding.id,
            FindingStatus.VALIDATED_CONFIRMED,
            notes="Confirmed via manual testing"
        )

        with temp_db.get_session() as session:
            updated = session.get(FindingTable, finding.id)
            assert updated.status == FindingStatus.VALIDATED_CONFIRMED
            assert updated.visual_validated is True

    def test_health_check(self, temp_db):
        """TASK-87: Test health check functionality."""
        result = temp_db.health_check()

        assert result["status"] == "healthy"
        assert result["sql_db"]["status"] == "healthy"
        assert result["vector_db"]["status"] == "healthy"
        assert result["latency_ms"] >= 0

    def test_get_metrics(self, temp_db):
        """TASK-88: Test metrics collection."""
        # Create some data first
        temp_db.get_or_create_target("https://metrics-test.example.com")

        metrics = temp_db.get_metrics()

        assert "pool" in metrics
        assert "tables" in metrics
        assert "vector_collections" in metrics
        assert metrics["tables"]["targets"] >= 1

    def test_backup_database(self, temp_db):
        """TASK-89: Test database backup functionality."""
        # Create some data to backup
        temp_db.get_or_create_target("https://backup-test.example.com")

        with tempfile.TemporaryDirectory() as backup_dir:
            result = temp_db.backup_database(backup_dir=backup_dir)

            assert result["status"] == "success"
            assert result["path"] is not None
            assert os.path.exists(result["path"])
            assert result["size_bytes"] > 0

    def test_connection_pooling_sqlite(self, temp_db):
        """TASK-85: Test that SQLite uses StaticPool."""
        from sqlalchemy.pool import StaticPool

        pool = temp_db.engine.pool
        assert isinstance(pool, StaticPool)


class TestDatabaseEnums:
    """Test enum definitions and conversions."""

    def test_scan_status_values(self):
        """Verify all expected ScanStatus values exist."""
        assert ScanStatus.PENDING.value == "PENDING"
        assert ScanStatus.RUNNING.value == "RUNNING"
        assert ScanStatus.COMPLETED.value == "COMPLETED"
        assert ScanStatus.STOPPED.value == "STOPPED"
        assert ScanStatus.FAILED.value == "FAILED"

    def test_finding_status_values(self):
        """Verify all expected FindingStatus values exist."""
        assert FindingStatus.PENDING_VALIDATION.value == "PENDING_VALIDATION"
        assert FindingStatus.VALIDATED_CONFIRMED.value == "VALIDATED_CONFIRMED"
        assert FindingStatus.VALIDATED_FALSE_POSITIVE.value == "VALIDATED_FALSE_POSITIVE"
        assert FindingStatus.MANUAL_REVIEW_RECOMMENDED.value == "MANUAL_REVIEW_RECOMMENDED"
        assert FindingStatus.SKIPPED.value == "SKIPPED"
        assert FindingStatus.ERROR.value == "ERROR"

    def test_enum_string_compatibility(self):
        """Test that enums work as strings for backwards compatibility."""
        # Enums inherit from str, so comparisons should work
        assert ScanStatus.RUNNING == "RUNNING"
        assert FindingStatus.PENDING_VALIDATION == "PENDING_VALIDATION"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
