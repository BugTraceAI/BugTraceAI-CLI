"""
Model-eval history — persists benchmark runs to a dedicated SQLite DB.

Kept in its own file (``data/model_eval_history.db``) so it never touches the
main scan schema/engine. The CLI API writes and serves these local runs to the
WEB "History" view.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("benchmark.history")


def _db_path() -> Path:
    data_dir = settings.BASE_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "model_eval_history.db"


def _summary_from_results(
    results: Dict[str, Any],
    model_count: int = 0,
    prompt_count: int = 0,
    runs: int = 1,
) -> Dict[str, int]:
    attempted = sum(int(record.get("total_calls") or 0) for record in results.values())
    planned = model_count * prompt_count * max(1, runs) if model_count and prompt_count else attempted
    return {
        "candidate_calls_planned": planned,
        "candidate_calls_attempted": attempted,
        "candidate_calls_failed": sum(int(record.get("failed") or 0) for record in results.values()),
        "candidate_calls_skipped": max(0, planned - attempted),
        "candidate_calls_evaluated": sum(int(record.get("evaluated_calls") or 0) for record in results.values()),
        "judge_calls_failed": sum(int(record.get("judge_failed") or 0) for record in results.values()),
        "models_failed": sum(
            1 for record in results.values() if record.get("task_error") or int(record.get("evaluated_calls") or 0) == 0
        ),
    }


def _status_from_summary(summary: Dict[str, Any]) -> str:
    failed_fields = ("candidate_calls_failed", "candidate_calls_skipped", "judge_calls_failed", "models_failed")
    return "PARTIAL" if any(int(summary.get(field) or 0) > 0 for field in failed_fields) else "COMPLETED"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS model_eval_runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT NOT NULL,
            judge        TEXT,
            model_count  INTEGER,
            top_model    TEXT,
            top_score    REAL,
            total_cost   REAL,
            judge_cost_usd REAL,
            cost_incomplete INTEGER NOT NULL DEFAULT 0,
            suite_id     TEXT NOT NULL DEFAULT 'legacy-v1',
            tier         TEXT NOT NULL DEFAULT 'legacy',
            prompt_count INTEGER,
            status       TEXT NOT NULL DEFAULT 'COMPLETED',
            summary_json TEXT,
            config_json  TEXT,
            ranked_json  TEXT,
            results_json TEXT
        )
        """)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(model_eval_runs)")}
    if "judge_cost_usd" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN judge_cost_usd REAL")
    if "cost_incomplete" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN cost_incomplete INTEGER NOT NULL DEFAULT 0")
    if "suite_id" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN suite_id TEXT NOT NULL DEFAULT 'legacy-v1'")
    if "tier" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN tier TEXT NOT NULL DEFAULT 'legacy'")
    if "prompt_count" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN prompt_count INTEGER")
    if "config_json" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN config_json TEXT")
    if "status" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN status TEXT NOT NULL DEFAULT 'COMPLETED'")
    if "summary_json" not in columns:
        conn.execute("ALTER TABLE model_eval_runs ADD COLUMN summary_json TEXT")

    rows = conn.execute("""SELECT id, model_count, prompt_count, config_json, results_json
           FROM model_eval_runs WHERE summary_json IS NULL""").fetchall()
    for row in rows:
        try:
            results = json.loads(row["results_json"] or "{}")
            config = json.loads(row["config_json"] or "{}")
            summary = _summary_from_results(
                results,
                model_count=int(row["model_count"] or len(results)),
                prompt_count=int(row["prompt_count"] or 0),
                runs=int(config.get("runs") or 1),
            )
            conn.execute(
                "UPDATE model_eval_runs SET status = ?, summary_json = ? WHERE id = ?",
                (_status_from_summary(summary), json.dumps(summary), row["id"]),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            conn.execute(
                "UPDATE model_eval_runs SET summary_json = ? WHERE id = ?",
                (json.dumps({}), row["id"]),
            )
    conn.commit()
    return conn


def save_run(judge: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a completed benchmark and return its summary row."""
    ranked: List[Dict[str, Any]] = result.get("ranked", []) or []
    created_at = datetime.now(timezone.utc).isoformat()
    if not ranked:
        return {"id": None, "created_at": created_at}

    top = next(
        (
            candidate
            for candidate in ranked
            if candidate.get("score_eligible", (candidate.get("evaluated_calls") or 0) > 0)
        ),
        None,
    )
    results = result.get("results", {}) or {}
    try:
        with _connect() as conn:
            cur = conn.execute(
                """INSERT INTO model_eval_runs
                   (created_at, judge, model_count, top_model, top_score, total_cost,
                      judge_cost_usd, cost_incomplete, suite_id, tier, prompt_count,
                      status, summary_json, config_json, ranked_json, results_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    created_at,
                    judge,
                    len(results) or len(ranked),
                    top.get("model") if top else None,
                    top.get("composite") if top else None,
                    result.get("total_cost_usd", 0.0),
                    result.get("judge_cost_usd", 0.0),
                    int(bool(result.get("cost_incomplete", False))),
                    result.get("suite_id", "legacy-v1"),
                    result.get("tier", "legacy"),
                    result.get("prompt_count"),
                    result.get("status", "COMPLETED"),
                    json.dumps(result.get("summary", {})),
                    json.dumps(result.get("config", {})),
                    json.dumps(ranked),
                    json.dumps(results),
                ),
            )
            run_id = cur.lastrowid
        return {"id": run_id, "created_at": created_at}
    except Exception as e:  # noqa: BLE001 — history is best-effort, never break a benchmark
        logger.warning(f"model-eval: could not persist run: {e}")
        return {"id": None, "created_at": created_at}


def list_runs(limit: int = 25) -> List[Dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                """SELECT id, created_at, judge, model_count, top_model, top_score,
                           total_cost, judge_cost_usd, cost_incomplete, suite_id,
                           tier, prompt_count, status, summary_json
                   FROM model_eval_runs ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        runs = [dict(r) for r in rows]
        for run in runs:
            run["cost_incomplete"] = bool(run.get("cost_incomplete"))
            run["summary"] = json.loads(run.pop("summary_json") or "{}")
        return runs
    except Exception as e:  # noqa: BLE001
        logger.warning(f"model-eval: could not list history: {e}")
        return []


def get_run(run_id: int) -> Optional[Dict[str, Any]]:
    try:
        with _connect() as conn:
            row = conn.execute("SELECT * FROM model_eval_runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["cost_incomplete"] = bool(out.get("cost_incomplete"))
        out["summary"] = json.loads(out.pop("summary_json") or "{}")
        out["config"] = json.loads(out.pop("config_json") or "{}")
        out["ranked"] = json.loads(out.pop("ranked_json") or "[]")
        out["results"] = json.loads(out.pop("results_json") or "{}")
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning(f"model-eval: could not read run {run_id}: {e}")
        return None


def delete_run(run_id: int) -> bool:
    """Delete one persisted benchmark run without touching scanner history."""
    try:
        with _connect() as conn:
            cursor = conn.execute("DELETE FROM model_eval_runs WHERE id = ?", (run_id,))
        return cursor.rowcount > 0
    except Exception as e:  # noqa: BLE001
        logger.warning(f"model-eval: could not delete run {run_id}: {e}")
        return False
