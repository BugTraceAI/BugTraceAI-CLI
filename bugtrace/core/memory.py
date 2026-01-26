import os
import asyncio
from asyncio import Lock
import aiofiles
from schemas.models import AgentState
from bugtrace.utils.logger import get_logger
logger = get_logger("core.memory")
import json

class ProjectMemory:
    def __init__(self, filename: str = "bugtrace_state.json"):
        self.filename = os.path.abspath(filename)
        self._write_lock = Lock()

    async def save_state(self, state: AgentState):
        """
        Atomically saves the state to disk.
        """
        async with self._write_lock:
            temp_file = f"{self.filename}.tmp"
            try:
                # 1. JSON Persistence (Runtime State)
                data = state.model_dump_json(indent=2)
                async with aiofiles.open(temp_file, mode='w') as f:
                    await f.write(data)
                os.replace(temp_file, self.filename)
                logger.debug(f"State saved to {self.filename}")
                
                # 2. SQL Persistence (Knowledge Graph)
                # We do this asynchronously or simply here. For safety/speed, let's just do it sync for now or offload.
                # Given this is "save_state", we typically want it safe.
                self._sync_to_db(state)
                
            except Exception as e:
                logger.error(f"Failed to save state: {e}")
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                raise
    
    def _sync_to_db(self, state: AgentState):
        from bugtrace.core.database import db_manager
        from schemas.db_models import TargetTable, ScanTable, FindingTable
        from sqlmodel import select
        
        if not state.current_target:
            return

        try:
            with db_manager.get_session() as session:
                # 1. Upsert Target
                statement = select(TargetTable).where(TargetTable.url == state.current_target.url)
                target_db = session.exec(statement).first()
                if not target_db:
                    target_db = TargetTable(url=state.current_target.url)
                    session.add(target_db)
                    session.commit()
                    session.refresh(target_db)
                
                # 2. Get or Create Scan (Simple logic: one active scan per target? or new scan per run?)
                # For now, let's assume we append findings to the latest scan or create one.
                # Let's create a scan if not exists for today.
                # Simplified: Just create a "Scan" for this session.
                # Ideally Orchestrator tracks scan_id, but here we just sync.
                # Let's query open scans.
                scan_stmt = select(ScanTable).where(ScanTable.target_id == target_db.id).order_by(ScanTable.timestamp.desc())
                scan_db = session.exec(scan_stmt).first()
                
                if not scan_db:
                    scan_db = ScanTable(target_id=target_db.id, status="IN_PROGRESS")
                    session.add(scan_db)
                    session.commit()
                    session.refresh(scan_db)

                # 3. Sync Findings
                # We need to avoid duplicates. Check by details/type.
                existing_findings = { (f.type, f.details) for f in scan_db.findings }
                
                for vuln in state.findings:
                    if (vuln.type.value, vuln.details) not in existing_findings:
                        finding_db = FindingTable(
                            scan_id=scan_db.id,
                            type=vuln.type,
                            severity=vuln.severity,
                            details=vuln.details or "",
                            payload_used=vuln.payload_used,
                            reflection_context=vuln.reflection_context,
                            confidence_score=vuln.confidence_score,
                            visual_validated=vuln.visual_validated,
                            attack_url=vuln.attack_url,
                            vuln_parameter=vuln.vuln_parameter
                        )
                        session.add(finding_db)
                        # Add to local cache to avoid re-adding in same loop if any
                        existing_findings.add((vuln.type.value, vuln.details))
                
                session.commit()
                logger.debug("State synced to Database.")
                
        except Exception as e:
            logger.error(f"DB Sync failed: {e}")

    async def load_state(self) -> AgentState:
        """
        Loads the state from disk, or returns a fresh state if missing.
        """
        if not os.path.exists(self.filename):
            logger.info("No existing state found. Creating new state.")
            return AgentState()
        
        try:
            async with aiofiles.open(self.filename, mode='r') as f:
                content = await f.read()
            
            # If empty file
            if not content.strip():
                return AgentState()
                
            return AgentState.model_validate_json(content)
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            # If state is corrupt, we might want to backup and start fresh, or fail hard.
            # For now, let's fail hard so we don't overwrite evidence.
            raise
