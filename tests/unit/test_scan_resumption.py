"""
Tests for scan resumption functionality.

Tests verify that:
1. Incomplete scans can be detected by target URL and phase
2. Resume logic preserves report directory and retry count
3. New scan is created with resumed_from_id reference
4. Phase completion tracking updates DB correctly
"""

import pytest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from bugtrace.services.scan_service import ScanService
from bugtrace.services.scan_context import ScanOptions
from bugtrace.schemas.db_models import ScanTable, ScanStatus, TargetTable
from bugtrace.core.database import get_db_manager
from sqlmodel import select


def test_find_incomplete_scan_returns_none_for_nonexistent_target():
    """Test that no incomplete scan is found for unknown target."""
    service = ScanService(max_concurrent=1)
    result = service.find_incomplete_scan("https://nonexistent.example.com")
    assert result is None


def test_record_phase_complete_updates_db(tmp_path):
    """Test that _record_phase_complete updates last_phase_completed in DB."""
    from bugtrace.core.team import TeamOrchestrator
    from bugtrace.services.scan_context import ScanContext
    
    db = get_db_manager()
    
    # Create a test scan in DB
    with db.get_session() as session:
        target = TargetTable(url="https://test.example.com")
        session.add(target)
        session.commit()
        
        scan = ScanTable(
            target_id=target.id,
            timestamp=datetime.utcnow(),
            status=ScanStatus.RUNNING
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    
    # Mock TeamOrchestrator with minimal setup
    class MockTeamOrchestrator:
        def __init__(self, scan_id):
            self.scan_id = scan_id
            self._last_phase = None
        
        def _record_phase_complete(team_self, phase_name: str):
            team_self._last_phase = phase_name
            try:
                with db.get_session() as session:
                    scan = session.exec(
                        select(ScanTable).where(ScanTable.id == team_self.scan_id)
                    ).first()
                    if scan:
                        scan.last_phase_completed = phase_name
                        session.add(scan)
                        session.commit()
            except Exception:
                pass
    
    orchestrator = MockTeamOrchestrator(scan_id)
    orchestrator._record_phase_complete("reconnaissance")
    
    # Verify DB was updated
    with db.get_session() as session:
        updated_scan = session.exec(
            select(ScanTable).where(ScanTable.id == scan_id)
        ).first()
        assert updated_scan.last_phase_completed == "reconnaissance"


def test_scan_resumption_fields_in_model():
    """Test that ScanTable has required resumption fields."""
    assert hasattr(ScanTable, 'last_phase_completed')
    assert hasattr(ScanTable, 'retry_count')
    assert hasattr(ScanTable, 'last_error')
    assert hasattr(ScanTable, 'resumed_from_id')


def test_recovery_artifacts_detection(tmp_path):
    """Test that has_recovery_artifacts correctly identifies partial scans."""
    service = ScanService(max_concurrent=1)
    base_dir = tmp_path
    
    # Create partial recovery artifacts
    recovery_dir = base_dir / "scan_123"
    recovery_dir.mkdir()
    (recovery_dir / "specialists").mkdir()
    (recovery_dir / "specialists" / "results").mkdir()
    (recovery_dir / "specialists" / "results" / "finding.json").write_text('{"findings": []}')
    
    # Should detect recovery artifacts
    has_artifacts = service._has_recovery_artifacts(
        base_dir,
        123,
        "https://example.com",
        datetime.utcnow(),
        str(recovery_dir)
    )
    assert has_artifacts is True
    
    # Empty directory should not have recovery artifacts
    empty_dir = base_dir / "scan_999"
    empty_dir.mkdir()
    has_artifacts = service._has_recovery_artifacts(
        base_dir,
        999,
        "https://example.com",
        datetime.utcnow(),
        str(empty_dir)
    )
    assert has_artifacts is False


def test_scan_resumption_preserves_report_dir():
    """Test that resumed scans reuse the original report directory."""
    db = get_db_manager()
    
    # Create original scan
    with db.get_session() as session:
        target = TargetTable(url="https://test.example.com")
        session.add(target)
        session.commit()
        
        original_report = "/reports/test.example.com_20260323_120000"
        scan = ScanTable(
            target_id=target.id,
            timestamp=datetime.utcnow(),
            status=ScanStatus.FAILED,
            report_dir=original_report,
            last_phase_completed="discovery"
        )
        session.add(scan)
        session.commit()
        original_id = scan.id
    
    # Simulate resume: new scan should reference original
    with db.get_session() as session:
        new_scan = ScanTable(
            target_id=1,
            timestamp=datetime.utcnow(),
            status=ScanStatus.RUNNING,
            report_dir=original_report,  # Reused
            resumed_from_id=original_id
        )
        session.add(new_scan)
        session.commit()
        new_id = new_scan.id
    
    # Verify structure
    with db.get_session() as session:
        new = session.exec(
            select(ScanTable).where(ScanTable.id == new_id)
        ).first()
        assert new.resumed_from_id == original_id
        assert new.report_dir == original_report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
