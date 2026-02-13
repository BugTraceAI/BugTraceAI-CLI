from typing import Optional, List
from datetime import datetime
from enum import Enum
from sqlmodel import SQLModel, Field, Relationship
from bugtrace.schemas.models import VulnType, ReflectionContext


class ScanStatus(str, Enum):
    """Status values for scan lifecycle."""
    PENDING = "PENDING"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class FindingStatus(str, Enum):
    """Status values for finding validation lifecycle."""
    PENDING_VALIDATION = "PENDING_VALIDATION"
    VALIDATED_CONFIRMED = "VALIDATED_CONFIRMED"
    VALIDATED_FALSE_POSITIVE = "VALIDATED_FALSE_POSITIVE"
    MANUAL_REVIEW_RECOMMENDED = "MANUAL_REVIEW_RECOMMENDED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"

class TargetTable(SQLModel, table=True):
    __tablename__ = "target"
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    scans: List["ScanTable"] = Relationship(back_populates="target")

class ScanTable(SQLModel, table=True):
    __tablename__ = "scan"
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    progress_percent: int = 0
    origin: str = Field(default="unknown")  # "cli", "web", or "unknown" — tracks where scan was launched
    report_dir: Optional[str] = Field(default=None)  # Absolute path to the unified report directory
    enrichment_status: Optional[str] = Field(default=None)  # "full", "partial", "none", "pending"
    scan_type: Optional[str] = Field(default=None)  # "full", "hunter", "manager", or agent names
    max_depth: Optional[int] = Field(default=None)  # Crawl depth used
    max_urls: Optional[int] = Field(default=None)  # Max URLs configured

    target: Optional[TargetTable] = Relationship(back_populates="scans")
    findings: List["FindingTable"] = Relationship(back_populates="scan")

from sqlalchemy import Text, Column, Index


class FindingTable(SQLModel, table=True):
    __tablename__ = "finding"
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")

    type: VulnType
    severity: str
    details: Optional[str] = None
    payload_used: Optional[str] = None
    reflection_context: Optional[ReflectionContext] = None
    confidence_score: float = 0.0
    visual_validated: bool = False

    # Status lifecycle with type-safe enum
    status: FindingStatus = Field(default=FindingStatus.PENDING_VALIDATION, index=True)
    validator_notes: Optional[str] = None
    proof_screenshot_path: Optional[str] = None

    attack_url: Optional[str] = None
    vuln_parameter: Optional[str] = None
    reproduction_command: Optional[str] = None  # Specialist tool command (e.g., sqlmap)

    scan: Optional[ScanTable] = Relationship(back_populates="findings")

    # Composite index for efficient queries filtering by scan and status
    __table_args__ = (
        Index("idx_finding_scan_status", "scan_id", "status"),
    )

class ScanStateTable(SQLModel, table=True):
    __tablename__ = "scan_state"
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", unique=True)
    state_json: str = Field(sa_column=Column(Text)) # Safe large text blob
    updated_at: datetime = Field(default_factory=datetime.utcnow)

# Vector Store Logic (LanceDB)
# We don't define LanceDB tables here as they are defined dynamically or via PyArrow, 
# but we can reference them.
