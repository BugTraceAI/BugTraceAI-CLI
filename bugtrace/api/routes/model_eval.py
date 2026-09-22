"""
Model Evaluation Endpoints — run the LLM model benchmark and stream results.

  GET  /api/model-eval/models          → list models available on the active provider
  POST /api/model-eval                 → start a benchmark job (background)
  GET  /api/model-eval/{job_id}/results→ fetch a job's status + results
  DELETE /api/model-eval/{job_id}       → cancel a running benchmark
  GET  /api/model-eval/history          → list persisted benchmark runs
  GET  /api/model-eval/history/{run_id} → fetch one persisted run
  DELETE /api/model-eval/history/{run_id} → delete one persisted run
  WS   /api/ws/model-eval/{job_id}     → stream live per-model progress events

Jobs run in-process (asyncio tasks); progress is buffered per job so a WebSocket
that connects late still replays everything. The benchmark itself lives in
``bugtrace/benchmark/model_eval_runner.py``.
"""

import asyncio
from typing import Any, Dict, List, Literal, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, field_validator

from bugtrace.benchmark import history
from bugtrace.benchmark.model_eval_runner import (
    DEFAULT_CONCURRENCY,
    DEFAULT_JUDGE,
    DEFAULT_MAX_TOKENS,
    DEFAULT_SUITE_ID,
    _provider_ctx,
    run_benchmark,
    select_run_judge,
    suite_metadata,
)
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("api.routes.model_eval")

router = APIRouter(tags=["model-eval"])


# ──── Request / response models ────


class ModelEvalRequest(BaseModel):
    models: List[str] = Field(..., min_length=1, max_length=20, description="OpenRouter model ids to benchmark")
    judge: Optional[str] = Field(default=None, description="Judge model id (defaults to a neutral strong model)")
    timeout: float = Field(default=45.0, ge=5, le=120)
    max_tokens: int = Field(default=DEFAULT_MAX_TOKENS, ge=32, le=2000)
    runs: int = Field(default=2, ge=1, le=5)  # 2 samples by default: kills runs=1 verdict noise
    concurrency: int = Field(default=DEFAULT_CONCURRENCY, ge=1, le=8)
    suite_id: Literal["quick-v2", "advanced-v1", "quick-v3", "advanced-v2"] = DEFAULT_SUITE_ID
    api_key: Optional[str] = Field(
        default=None,
        description="OpenRouter API key supplied by the ModelLab module; overrides the CLI provider key when present.",
    )
    mutation_probe: bool = Field(
        default=False,
        description="Experimental: also sample each model at scan temperature and score MUTATION payload diversity (adds a few calls per model).",
    )

    @field_validator("api_key")
    @classmethod
    def normalize_api_key(cls, api_key: Optional[str]) -> Optional[str]:
        if api_key is None:
            return None
        api_key = api_key.strip()
        return api_key or None

    @field_validator("models")
    @classmethod
    def deduplicate_models(cls, models: List[str]) -> List[str]:
        cleaned = [model.strip() for model in models]
        if any(not model for model in cleaned):
            raise ValueError("Model ids cannot be empty")
        return list(dict.fromkeys(cleaned))

    @field_validator("judge")
    @classmethod
    def validate_judge(cls, judge: Optional[str]) -> Optional[str]:
        if judge is None:
            return None
        judge = judge.strip()
        if not judge:
            raise ValueError("Judge model id cannot be empty")
        return judge


# ──── In-process job registry ────


class _Job:
    def __init__(self, job_id: int, req: ModelEvalRequest):
        self.id = job_id
        self.req = req
        self.api_key_override = req.api_key
        self.requested_judge = req.judge or DEFAULT_JUDGE
        self.judge = select_run_judge(req.models, self.requested_judge)
        self.suite = suite_metadata(req.suite_id)
        self.status = "RUNNING"  # RUNNING | COMPLETED | PARTIAL | FAILED | CANCELLED
        self.buffer: List[Dict[str, Any]] = []
        self.subscribers: List[asyncio.Queue] = []
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.task: Optional[asyncio.Task] = None  # strong ref so the bg task isn't GC-cancelled
        self._end_emitted = False

    async def emit(self, event_type: str, data: Dict[str, Any]) -> None:
        evt = {"event_type": event_type, "data": data}
        self.buffer.append(evt)
        for q in list(self.subscribers):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                if event_type == "_end":
                    try:
                        q.get_nowait()
                        q.put_nowait(evt)
                    except (asyncio.QueueEmpty, asyncio.QueueFull):
                        logger.warning(f"model-eval job {self.id}: could not enqueue terminal event")
                else:
                    logger.warning(f"model-eval job {self.id}: subscriber queue full, dropping {event_type}")

    async def emit_end(self) -> None:
        if self._end_emitted:
            return
        self._end_emitted = True
        await self.emit("_end", {"status": self.status})


_JOBS: Dict[int, _Job] = {}
_JOB_SEQ = {"n": 0}
_MAX_JOBS = 50  # keep memory bounded; evict oldest finished jobs
_MAX_RUNNING_JOBS = 3
_MAX_CANDIDATE_CALLS_PER_JOB = 120
_SUPPORTED_PROVIDERS = {"openrouter", "openrouter-v2"}


def _job_is_active(job: _Job) -> bool:
    return job.status == "RUNNING" or bool(job.task and not job.task.done())


def _evict_old_jobs() -> None:
    if len(_JOBS) <= _MAX_JOBS:
        return
    finished = [jid for jid, job in _JOBS.items() if not _job_is_active(job)]
    for jid in sorted(finished)[: len(_JOBS) - _MAX_JOBS]:
        _JOBS.pop(jid, None)


def _require_supported_provider() -> None:
    provider = str(settings.PROVIDER or "").strip().lower()
    if provider not in _SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail="ModelLab beta currently supports OpenRouter only. Select an OpenRouter provider before running it.",
        )


async def _unavailable_models(base_url: str, headers: Dict[str, str], model_ids: List[str]) -> List[str]:
    """Return OpenRouter models that currently have no serving endpoint."""
    try:
        if httpx.URL(base_url).host != "openrouter.ai":
            return []
    except Exception:
        return []

    models_url = base_url.replace("/chat/completions", "/models").rstrip("/")

    async def check(client: httpx.AsyncClient, model_id: str) -> Optional[str]:
        try:
            response = await client.get(f"{models_url}/{model_id}/endpoints", headers=headers)
            if response.status_code == 404:
                return model_id
            if response.status_code != 200:
                return None
            data = response.json().get("data") or {}
            endpoints = data.get("endpoints")
            return model_id if isinstance(endpoints, list) and not endpoints else None
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            logger.warning(f"model-eval: availability preflight failed for {model_id}: {exc}")
            return None

    unique_ids = list(dict.fromkeys(model_ids))
    async with httpx.AsyncClient(timeout=10.0) as client:
        checked = await asyncio.gather(*(check(client, model_id) for model_id in unique_ids))
    return [model_id for model_id in checked if model_id is not None]


# ──── Endpoints ────


@router.get("/model-eval/models")
async def list_models(x_openrouter_key: Optional[str] = Header(default=None)):
    """Proxy the model catalog. Uses the ModelLab module key (X-OpenRouter-Key header) when
    supplied, otherwise the CLI's active provider (key stays server-side either way)."""
    override = (x_openrouter_key or "").strip() or None
    if not override:
        _require_supported_provider()
    base_url, api_key, headers = _provider_ctx(override)
    if not api_key:
        raise HTTPException(status_code=400, detail="No OpenRouter API key: enter one in the ModelLab module or configure the CLI provider.")
    models_url = base_url.replace("/chat/completions", "/models")
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(models_url, headers=headers)
            resp.raise_for_status()
            data = resp.json().get("data", [])
    except (httpx.HTTPError, ValueError, KeyError) as e:
        raise HTTPException(status_code=502, detail=f"Could not fetch model catalog: {e}")

    models = [
        {"id": m.get("id"), "name": m.get("name") or m.get("id"), "pricing": m.get("pricing", {})}
        for m in data
        if m.get("id")
    ]
    return {"provider": settings.PROVIDER, "count": len(models), "models": models}


@router.get("/model-eval/test-key")
async def test_key(x_openrouter_key: Optional[str] = Header(default=None)):
    """Validate an OpenRouter API key BEFORE running a benchmark.

    Hits OpenRouter's *authenticated* `/key` endpoint (returns the key's label + credit
    limits, consumes zero tokens) — unlike `/models`, which is public and returns 200 even
    for a bad key. Uses the ModelLab module key (X-OpenRouter-Key header) when supplied,
    else the CLI's configured provider key. The key never leaves the server.
    """
    override = (x_openrouter_key or "").strip() or None
    if not override:
        _require_supported_provider()
    base_url, api_key, headers = _provider_ctx(override)
    if not api_key:
        raise HTTPException(status_code=400, detail="No OpenRouter API key: enter one in the ModelLab module or configure the CLI provider.")
    key_url = base_url.replace("/chat/completions", "/key")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(key_url, headers=headers)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach OpenRouter to validate the key: {e}")
    if resp.status_code == 200:
        try:
            info = resp.json().get("data", {}) or {}
        except ValueError:
            info = {}
        return {
            "valid": True,
            "label": info.get("label"),
            "usage": info.get("usage"),
            "limit": info.get("limit"),
            "is_free_tier": info.get("is_free_tier"),
        }
    if resp.status_code in (401, 403):
        return {"valid": False, "detail": "OpenRouter rejected this key (401/403). Check it's correct and active."}
    return {"valid": False, "detail": f"Unexpected OpenRouter response ({resp.status_code})."}


@router.get("/model-eval/history")
async def list_history(limit: int = 25):
    """List recent benchmark runs (newest first)."""
    return {"runs": history.list_runs(limit=max(1, min(100, limit)))}


@router.get("/model-eval/history/{run_id}")
async def get_history_run(run_id: int):
    """Fetch a single persisted benchmark run with its full ranked results."""
    run = history.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"History run {run_id} not found")
    return run


@router.delete("/model-eval/history/{run_id}")
async def delete_history_run(run_id: int):
    """Delete one persisted benchmark run."""
    if not history.delete_run(run_id):
        raise HTTPException(status_code=404, detail=f"History run {run_id} not found")
    return {"deleted": True, "id": run_id}


@router.post("/model-eval")
async def start_model_eval(req: ModelEvalRequest):
    """Start a benchmark job and return its id + WebSocket url for live progress."""
    # ModelLab may run with its own OpenRouter key (req.api_key) independent of the CLI provider.
    if not req.api_key:
        _require_supported_provider()
    base_url, api_key, headers = _provider_ctx(req.api_key)
    if not api_key:
        raise HTTPException(status_code=400, detail="No OpenRouter API key: enter one in the ModelLab module or configure the CLI provider.")
    if sum(_job_is_active(job) for job in _JOBS.values()) >= _MAX_RUNNING_JOBS:
        raise HTTPException(status_code=429, detail="At most 3 model evaluation jobs may run concurrently.")
    prompt_count = suite_metadata(req.suite_id)["prompt_count"]
    candidate_calls = len(req.models) * prompt_count * req.runs
    if candidate_calls > _MAX_CANDIDATE_CALLS_PER_JOB:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Benchmark requests at most {_MAX_CANDIDATE_CALLS_PER_JOB} candidate calls per job; "
                f"this configuration requests {candidate_calls}. Reduce models or runs."
            ),
        )

    try:
        effective_judge = select_run_judge(req.models, req.judge or DEFAULT_JUDGE)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    unavailable = await _unavailable_models(base_url, headers, [*req.models, effective_judge])
    if unavailable:
        raise HTTPException(
            status_code=400,
            detail=(
                "No active provider endpoint is available for: "
                f"{', '.join(unavailable)}. Remove or replace these models before running the benchmark."
            ),
        )

    _JOB_SEQ["n"] += 1
    job_id = _JOB_SEQ["n"]
    try:
        job = _Job(job_id, req)
    except ValueError as exc:
        _JOB_SEQ["n"] -= 1
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _JOBS[job_id] = job
    _evict_old_jobs()

    async def _run() -> None:
        try:
            res = await run_benchmark(
                models=req.models,
                judge_model=job.judge,
                timeout=req.timeout,
                max_tokens=req.max_tokens,
                runs=req.runs,
                concurrency=req.concurrency,
                suite_id=req.suite_id,
                on_event=job.emit,
                api_key_override=job.api_key_override,
                mutation_probe=req.mutation_probe,
            )
            job.result = res
            if job.status == "CANCELLED":
                return
            if not isinstance(res, dict) or res.get("suite_id") != req.suite_id:
                job.status = "FAILED"
                job.error = f"Benchmark suite mismatch: expected {req.suite_id}."
                await job.emit("error", {"message": job.error})
                return
            results = res.get("results") if isinstance(res, dict) else None
            has_evaluated_model = bool(results) and any(
                isinstance(record, dict) and not record.get("task_error") and (record.get("evaluated_calls") or 0) > 0
                for record in results.values()
            )
            if not isinstance(res, dict) or not res.get("ranked") or not has_evaluated_model:
                job.status = "FAILED"
                job.error = "Benchmark returned no evaluated model results."
                await job.emit("error", {"message": job.error})
                return

            summary = res.get("summary") or {}
            has_execution_failures = any(
                int(summary.get(field) or 0) > 0
                for field in (
                    "candidate_calls_failed",
                    "candidate_calls_skipped",
                    "judge_calls_failed",
                    "models_failed",
                )
            )
            job.status = "PARTIAL" if has_execution_failures else "COMPLETED"
            res["status"] = job.status
            saved = history.save_run(job.judge, res)
            await job.emit("saved", {"history_id": saved.get("id")})
        except asyncio.CancelledError:
            if job.status != "CANCELLED":
                job.status = "CANCELLED"
                await job.emit("cancelled", {"status": job.status})
            raise
        except Exception as e:  # noqa: BLE001
            if job.status == "CANCELLED":
                return
            logger.exception(f"model-eval job {job_id} failed")
            job.status = "FAILED"
            job.error = str(e)[:200]
            await job.emit("error", {"message": job.error})
        finally:
            await job.emit_end()
            _evict_old_jobs()

    job.task = asyncio.create_task(_run())  # keep a strong ref (job is held in _JOBS)
    return {
        "job_id": job_id,
        "status": "RUNNING",
        "ws_url": f"/api/ws/model-eval/{job_id}",
        "judge": job.judge,
        **job.suite,
    }


@router.get("/model-eval/{job_id}/results")
async def get_model_eval_results(job_id: int):
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Benchmark job {job_id} not found")
    return {
        "job_id": job_id,
        "status": job.status,
        "result": job.result,
        "error": job.error,
        "judge": job.judge,
        **job.suite,
    }


@router.delete("/model-eval/{job_id}")
async def cancel_model_eval(job_id: int):
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Benchmark job {job_id} not found")
    if job.status not in ("RUNNING", "CANCELLED"):
        return {"job_id": job_id, "status": job.status}

    if job.status == "RUNNING":
        job.status = "CANCELLED"
        await job.emit("cancelled", {"status": job.status})

    task = job.task
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await job.emit_end()
    _evict_old_jobs()
    return {"job_id": job_id, "status": job.status}


@router.websocket("/ws/model-eval/{job_id}")
async def websocket_model_eval(websocket: WebSocket, job_id: int):
    """Stream a job's progress events; replays the buffer so late clients catch up."""
    await websocket.accept()
    job = _JOBS.get(job_id)
    if not job:
        await websocket.close(code=1008, reason=f"Unknown job {job_id}")
        return

    queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
    job.subscribers.append(queue)
    try:
        # Replay everything buffered so far.
        for evt in list(job.buffer):
            await websocket.send_json(evt)
            if evt["event_type"] == "_end":
                await websocket.close(code=1000, reason="Benchmark complete")
                return
        # Then stream live events until the job ends.
        while True:
            evt = await queue.get()
            await websocket.send_json(evt)
            if evt["event_type"] == "_end":
                break
        await websocket.close(code=1000, reason="Benchmark complete")
    except WebSocketDisconnect:
        logger.info(f"model-eval WS disconnected from job {job_id}")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"model-eval WS error on job {job_id}: {e}")
    finally:
        if queue in job.subscribers:
            job.subscribers.remove(queue)
