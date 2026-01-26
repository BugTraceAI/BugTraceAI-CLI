import sqlite3
import json
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime
from loguru import logger

class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"

class JobManager:
    """
    Manages the persistent Job Queue backed by SQLite.
    Allows pause/resume and crash recovery.

    TASK-13: Added dead letter queue for jobs that fail repeatedly.
    Jobs are moved to dead_letter_queue after MAX_RETRIES failures.
    """

    MAX_RETRIES = 3  # Jobs moved to dead letter after this many failures

    def __init__(self, db_path: str = "state/jobs.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create Jobs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                params JSON,
                status TEXT DEFAULT 'PENDING',
                priority INTEGER DEFAULT 10,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                result JSON,
                error TEXT,
                retry_count INTEGER DEFAULT 0
            )
        """)

        # TASK-13: Create Dead Letter Queue table for permanently failed jobs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dead_letter_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_job_id INTEGER,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                params JSON,
                retry_count INTEGER,
                last_error TEXT,
                error_history JSON,
                created_at TIMESTAMP,
                moved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add retry_count column if missing (migration for existing DBs)
        try:
            cursor.execute("ALTER TABLE jobs ADD COLUMN retry_count INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists

        conn.commit()
        conn.close()

    def add_job(self, job_type: str, target: str, params: Dict[str, Any] = {}, priority: int = 10) -> int:
        """Adds a new job to the queue."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Deduplication check (Don't add same job twice if pending)
        cursor.execute(
            "SELECT id FROM jobs WHERE type=? AND target=? AND params=? AND status='PENDING'", 
            (job_type, target, json.dumps(params))
        )
        if cursor.fetchone():
            conn.close()
            return -1 # Duplicate
            
        cursor.execute(
            "INSERT INTO jobs (type, target, params, priority) VALUES (?, ?, ?, ?)",
            (job_type, target, json.dumps(params), priority)
        )
        job_id = cursor.lastrowid
        conn.commit()
        conn.close()
        logger.info(f"➕ Job Added: {job_type} -> {target} (ID: {job_id})")
        return job_id

    def get_next_job(self) -> Optional[Dict]:
        """Fetches the next highest priority PENDING job atomically.

        Uses UPDATE ... RETURNING (SQLite 3.35+) to ensure atomic fetch-and-lock
        preventing race conditions where two workers could grab the same job.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Access by name
        cursor = conn.cursor()

        try:
            # Atomic fetch-and-lock using UPDATE ... RETURNING
            # This prevents race conditions between SELECT and UPDATE
            cursor.execute("""
                UPDATE jobs
                SET status='RUNNING'
                WHERE id = (
                    SELECT id FROM jobs
                    WHERE status='PENDING'
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                )
                RETURNING *
            """)
            row = cursor.fetchone()
            conn.commit()

            if row:
                job = dict(row)
                job['params'] = json.loads(job['params'])
                return job

            return None
        finally:
            conn.close()

    def complete_job(self, job_id: int, result: Dict, status: JobStatus = JobStatus.COMPLETED, error: str = None):
        """Marks a job as finished."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE jobs SET status=?, result=?, error=? WHERE id=?",
            (status.value, json.dumps(result), error, job_id)
        )
        conn.commit()
        conn.close()
        logger.info(f"✅ Job {job_id} Completed: {status.value}")

    def reset_running_jobs(self):
        """Called on startup to reset jobs that crashed while RUNNING."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE jobs SET status='PENDING' WHERE status='RUNNING'")
        changes = cursor.rowcount
        conn.commit()
        conn.close()
        if changes > 0:
            logger.warning(f"🔄 Reset {changes} crashed jobs to PENDING status.")

    # TASK-13: Dead Letter Queue Methods

    def fail_job_with_retry(self, job_id: int, error: str) -> bool:
        """
        Handle job failure with retry logic.
        Returns True if job was moved to dead letter queue, False if retrying.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            # Get current job state
            cursor.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
            job = cursor.fetchone()

            if not job:
                logger.error(f"Job {job_id} not found for retry handling")
                return False

            retry_count = (job['retry_count'] or 0) + 1

            if retry_count >= self.MAX_RETRIES:
                # Move to dead letter queue
                self._move_to_dead_letter(cursor, job, error)
                conn.commit()
                logger.warning(f"💀 Job {job_id} moved to dead letter queue after {retry_count} failures")
                return True
            else:
                # Increment retry count and reset to PENDING
                cursor.execute(
                    "UPDATE jobs SET status='PENDING', retry_count=?, error=? WHERE id=?",
                    (retry_count, error, job_id)
                )
                conn.commit()
                logger.info(f"🔄 Job {job_id} will retry (attempt {retry_count + 1}/{self.MAX_RETRIES})")
                return False
        finally:
            conn.close()

    def _move_to_dead_letter(self, cursor, job: sqlite3.Row, final_error: str):
        """Move a failed job to the dead letter queue."""
        # Build error history
        error_history = [final_error]
        if job['error']:
            error_history.insert(0, job['error'])

        cursor.execute("""
            INSERT INTO dead_letter_queue
                (original_job_id, type, target, params, retry_count, last_error, error_history, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job['id'],
            job['type'],
            job['target'],
            job['params'],
            job['retry_count'] + 1,
            final_error,
            json.dumps(error_history),
            job['created_at']
        ))

        # Remove from jobs table
        cursor.execute("DELETE FROM jobs WHERE id=?", (job['id'],))

    def get_dead_letter_jobs(self, limit: int = 100) -> List[Dict]:
        """Retrieve jobs from the dead letter queue."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM dead_letter_queue
            ORDER BY moved_at DESC
            LIMIT ?
        """, (limit,))

        jobs = [dict(row) for row in cursor.fetchall()]
        conn.close()

        for job in jobs:
            job['params'] = json.loads(job['params']) if job['params'] else {}
            job['error_history'] = json.loads(job['error_history']) if job['error_history'] else []

        return jobs

    def requeue_dead_letter_job(self, dlq_id: int) -> Optional[int]:
        """Move a job from dead letter queue back to jobs table for retry."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM dead_letter_queue WHERE id=?", (dlq_id,))
            dlq_job = cursor.fetchone()

            if not dlq_job:
                logger.error(f"Dead letter job {dlq_id} not found")
                return None

            # Re-add to jobs with reset retry count
            cursor.execute("""
                INSERT INTO jobs (type, target, params, status, priority, retry_count)
                VALUES (?, ?, ?, 'PENDING', 10, 0)
            """, (dlq_job['type'], dlq_job['target'], dlq_job['params']))

            new_job_id = cursor.lastrowid

            # Remove from dead letter queue
            cursor.execute("DELETE FROM dead_letter_queue WHERE id=?", (dlq_id,))

            conn.commit()
            logger.info(f"♻️ Dead letter job {dlq_id} requeued as job {new_job_id}")
            return new_job_id
        finally:
            conn.close()

    def get_dead_letter_count(self) -> int:
        """Get the count of jobs in the dead letter queue."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dead_letter_queue")
        count = cursor.fetchone()[0]
        conn.close()
        return count
