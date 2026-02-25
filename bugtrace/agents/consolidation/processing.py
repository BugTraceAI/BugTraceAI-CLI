"""
Consolidation Processing

I/O layer for LLM-based dedup calls, queue management,
and finding distribution to specialist queues.

Extracted from thinking_consolidation_agent.py for modularity.
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional
from loguru import logger

from bugtrace.core.event_bus import EventType
from bugtrace.core.dedup_metrics import dedup_metrics
from bugtrace.agents.consolidation.core import (
    DeduplicationCache,
    PrioritizedFinding,
    classify_finding,
    calculate_priority,
    classify_and_prioritize,
)


async def persist_queue_item(  # I/O
    specialist: str,
    finding: Dict[str, Any],
    scan_context: str,
    scan_id: Optional[int],
    get_queues_dir_fn,
    queue_write_lock: asyncio.Lock,
    agent_name: str = "ThinkingAgent",
) -> None:
    """
    Persist finding to a file-based queue for durability and auditing.

    File structure (v3.2 - JSON Lines format):
    - reports/{scan_id}/specialists/wet/{specialist}.json

    Args:
        specialist: Specialist queue name
        finding: Finding dictionary to persist
        scan_context: Scan context string
        scan_id: Optional scan ID for DB persistence
        get_queues_dir_fn: Callable that returns the wet dir path
        queue_write_lock: Lock for thread-safe file writes
        agent_name: Name for logging
    """
    try:
        wet_dir = get_queues_dir_fn()

        # Encode complex payloads as base64
        from bugtrace.core.payload_format import encode_finding_payloads
        encoded_finding = encode_finding_payloads(finding)

        queue_entry = {
            "timestamp": time.time(),
            "specialist": specialist,
            "scan_context": scan_context,
            "finding": encoded_finding
        }

        queue_file = wet_dir / f"{specialist}.json"
        async with queue_write_lock:
            with open(queue_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(queue_entry, ensure_ascii=False, separators=(',', ':')) + "\n")

        # Persist to SQLite Database
        if scan_id:
            try:
                from bugtrace.core.database import get_db_manager
                db = get_db_manager()
                await asyncio.to_thread(
                    db.save_scan_result,
                    target_url=finding.get("url", "unknown"),
                    findings=[finding],
                    scan_id=scan_id
                )
            except Exception as db_err:
                logger.error(f"[{agent_name}] Failed to save finding to DB: {db_err}")

    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to persist queue item: {e}")


async def distribute_to_queue(  # I/O
    prioritized: PrioritizedFinding,
    scan_context: str,
    scan_id: Optional[int],
    get_queues_dir_fn,
    queue_write_lock: asyncio.Lock,
    stats: Dict[str, Any],
    backpressure_retries: int = 3,
    backpressure_delay: float = 1.0,
    verbose_emitter=None,
    agent_name: str = "ThinkingAgent",
) -> bool:
    """
    Distribute a prioritized finding to the appropriate specialist queue.

    Handles backpressure by retrying with exponential backoff.

    Args:
        prioritized: PrioritizedFinding with specialist and priority
        scan_context: Scan context string
        scan_id: Optional scan ID for DB persistence
        get_queues_dir_fn: Callable that returns the wet dir path
        queue_write_lock: Lock for file writes
        stats: Statistics dict (mutated)
        backpressure_retries: Number of retries on full queue
        backpressure_delay: Base delay between retries
        verbose_emitter: Optional verbose event emitter
        agent_name: Name for logging

    Returns:
        True if successfully queued, False if queue full after retries
    """
    from bugtrace.core.queue import queue_manager

    # Persist to file first (Durability)
    await persist_queue_item(
        prioritized.specialist,
        prioritized.finding,
        scan_context,
        scan_id,
        get_queues_dir_fn,
        queue_write_lock,
        agent_name,
    )

    specialist = prioritized.specialist
    queue = queue_manager.get_queue(specialist)
    payload = prioritized.queue_payload

    for attempt in range(backpressure_retries):
        success = await queue.enqueue(payload, prioritized.scan_context)

        if success:
            stats["distributed"] += 1
            stats["by_specialist"][specialist] = \
                stats["by_specialist"].get(specialist, 0) + 1

            if verbose_emitter:
                verbose_emitter.emit("strategy.finding.queued", {
                    "specialist": specialist,
                    "priority": round(prioritized.priority, 1),
                    "queue_depth": queue.depth() if hasattr(queue, 'depth') else -1,
                })
            logger.debug(
                f"[{agent_name}] Queued: {prioritized.finding.get('type')} -> "
                f"{specialist} (priority: {prioritized.priority:.1f})"
            )
            return True

        # Backpressure
        delay = backpressure_delay * (2 ** attempt)
        if verbose_emitter:
            verbose_emitter.emit("strategy.finding.backpressure", {
                "specialist": specialist, "retry": attempt + 1, "delay_ms": int(delay * 1000),
            })
        logger.warning(
            f"[{agent_name}] Queue {specialist} full, retry {attempt + 1}/"
            f"{backpressure_retries} in {delay:.1f}s"
        )
        await asyncio.sleep(delay)

    # Failed after all retries
    stats.setdefault("backpressure_drops", 0)
    stats["backpressure_drops"] += 1
    logger.error(
        f"[{agent_name}] Dropped finding: {prioritized.finding.get('type')} -> "
        f"{specialist} (queue full after {backpressure_retries} retries)"
    )
    return False


async def emit_work_queued_event(  # I/O
    prioritized: PrioritizedFinding,
    event_bus,
    emit_events: bool = True,
    agent_name: str = "ThinkingAgent",
) -> None:
    """
    Emit work_queued_{specialist} event for downstream coordination.

    Args:
        prioritized: The distributed finding
        event_bus: Event bus instance
        emit_events: Whether to actually emit
        agent_name: Name for logging
    """
    if not emit_events:
        return

    specialist_to_event = {
        "xss": EventType.WORK_QUEUED_XSS,
        "sqli": EventType.WORK_QUEUED_SQLI,
        "csti": EventType.WORK_QUEUED_CSTI,
        "lfi": EventType.WORK_QUEUED_LFI,
        "idor": EventType.WORK_QUEUED_IDOR,
        "rce": EventType.WORK_QUEUED_RCE,
        "ssrf": EventType.WORK_QUEUED_SSRF,
        "xxe": EventType.WORK_QUEUED_XXE,
        "jwt": EventType.WORK_QUEUED_JWT,
        "openredirect": EventType.WORK_QUEUED_OPENREDIRECT,
        "prototype_pollution": EventType.WORK_QUEUED_PROTOTYPE_POLLUTION,
        "header_injection": EventType.WORK_QUEUED_HEADER_INJECTION,
    }

    event_type = specialist_to_event.get(prioritized.specialist)
    if not event_type:
        logger.warning(f"[{agent_name}] No event type for specialist: {prioritized.specialist}")
        return

    event_data = {
        "specialist": prioritized.specialist,
        "finding": {
            "type": prioritized.finding.get("type"),
            "parameter": prioritized.finding.get("parameter"),
            "url": prioritized.finding.get("url"),
            "severity": prioritized.finding.get("severity"),
            "fp_confidence": prioritized.finding.get("fp_confidence"),
        },
        "priority": prioritized.priority,
        "scan_context": prioritized.scan_context,
        "timestamp": time.time(),
    }

    try:
        await event_bus.emit(event_type, event_data)
        logger.debug(f"[{agent_name}] Emitted {event_type.value}")
    except Exception as e:
        logger.error(f"[{agent_name}] Failed to emit {event_type.value}: {e}")


def should_bypass_fp_filter(  # PURE
    specialist: str,
    fp_confidence: float,
    skeptical_score: float,
    finding: Dict[str, Any],
) -> bool:
    """
    Determine whether a finding should bypass the false-positive filter.

    Certain findings bypass this filter because their specialist agents
    are the authoritative judges.

    Args:
        specialist: Classified specialist queue name
        fp_confidence: FP confidence score (0.0-1.0)
        skeptical_score: Skeptical review score (0-10)
        finding: Finding dictionary

    Returns:
        True if the finding should bypass FP filtering
    """
    is_sqli = specialist == "sqli"
    is_template_injection = specialist == "csti"
    is_lfi = specialist == "lfi"
    is_rce = specialist == "rce"
    is_probe_validated = finding.get("probe_validated", False)
    has_high_skeptical_score = skeptical_score >= 6

    return (is_sqli or is_template_injection or is_lfi or is_rce
            or is_probe_validated or has_high_skeptical_score)


def normalize_skeptical_score(skeptical_score: Any) -> float:  # PURE
    """
    Normalize skeptical_score if legacy 0-1 scale (convert to 0-10).

    Args:
        skeptical_score: Raw score value

    Returns:
        Normalized score on 0-10 scale
    """
    if isinstance(skeptical_score, (int, float)) and skeptical_score < 1.1:
        return skeptical_score * 10
    return float(skeptical_score)


async def process_finding(  # I/O
    finding: Dict[str, Any],
    scan_context: str,
    dedup_cache: DeduplicationCache,
    stats: Dict[str, Any],
    scan_id: Optional[int],
    get_queues_dir_fn,
    queue_write_lock: asyncio.Lock,
    event_bus,
    fp_threshold: float = 0.3,
    backpressure_retries: int = 3,
    backpressure_delay: float = 1.0,
    emit_events: bool = True,
    verbose_emitter=None,
    agent_name: str = "ThinkingAgent",
    **classify_kwargs,
) -> None:
    """
    Process a single finding through the full pipeline.

    Steps:
    1. Record received (for metrics)
    2. Check fp_confidence threshold
    3. Check deduplication cache
    4. Classify and prioritize
    5. Distribute to specialist queue
    6. Emit work_queued event

    Args:
        finding: Finding dictionary
        scan_context: Scan context string
        dedup_cache: DeduplicationCache instance
        stats: Statistics dict (mutated)
        scan_id: Optional scan ID for DB persistence
        get_queues_dir_fn: Callable that returns the wet dir path
        queue_write_lock: Lock for file writes
        event_bus: Event bus instance
        fp_threshold: False positive threshold
        backpressure_retries: Retries on full queue
        backpressure_delay: Base delay between retries
        emit_events: Whether to emit events
        verbose_emitter: Optional verbose event emitter
        agent_name: Name for logging
        **classify_kwargs: Passed to classify_finding
    """
    # 1. Get specialist type for metrics
    logger.debug(f"[{agent_name}] Step 1: Classifying finding type={finding.get('type')}")
    specialist = classify_finding(finding, stats, agent_name=agent_name, **classify_kwargs) or "unknown"
    dedup_metrics.record_received(specialist)
    if verbose_emitter:
        verbose_emitter.progress("strategy.finding.received", {
            "type": finding.get("type"), "param": finding.get("parameter"), "specialist": specialist,
        }, every=10)
    logger.debug(f"[{agent_name}] Step 1 done: specialist={specialist}")

    # 2. FP confidence filter
    fp_confidence = finding.get("fp_confidence", 0.5)
    skeptical_score = normalize_skeptical_score(finding.get("skeptical_score", 5))

    bypass = should_bypass_fp_filter(specialist, fp_confidence, skeptical_score, finding)

    if not bypass and fp_confidence < fp_threshold:
        if verbose_emitter:
            verbose_emitter.emit("strategy.finding.fp_filtered", {
                "type": finding.get("type"), "param": finding.get("parameter"),
                "fp_confidence": fp_confidence,
            })
        logger.debug(f"[{agent_name}] FP filtered: {finding.get('type')} "
                     f"(fp_confidence: {fp_confidence:.2f} < {fp_threshold})")
        stats["fp_filtered"] += 1
        dedup_metrics.record_fp_filtered()
        return

    # Log bypass reasons
    if bypass and fp_confidence < fp_threshold:
        if specialist == "sqli":
            logger.info(f"[{agent_name}] SQLi bypass: forwarded to SQLMap for validation")
        elif specialist == "csti":
            logger.info(f"[{agent_name}] Template injection bypass: forwarded to CSTIAgent")
        elif specialist == "lfi":
            logger.info(f"[{agent_name}] LFI bypass: forwarded to LFIAgent")
        elif specialist == "rce":
            logger.info(f"[{agent_name}] RCE bypass: too critical to filter")
        if skeptical_score >= 6:
            logger.info(f"[{agent_name}] Skeptical review bypass: score {skeptical_score}/10 >= 6")

    # 3. Deduplication check
    logger.debug(f"[{agent_name}] Step 3: Checking dedup cache")
    is_duplicate, key = await dedup_cache.check_and_add(finding, scan_context)
    logger.debug(f"[{agent_name}] Step 3 done: duplicate={is_duplicate}")
    if is_duplicate:
        if verbose_emitter:
            verbose_emitter.emit("strategy.finding.duplicate", {
                "type": finding.get("type"), "param": finding.get("parameter"), "dedup_key": key,
            })
        stats["duplicates_filtered"] += 1
        dedup_metrics.record_duplicate(specialist, key)
        return

    # 4. Classify and prioritize
    logger.debug(f"[{agent_name}] Step 4: Classify and prioritize")
    prioritized = classify_and_prioritize(finding, scan_context, stats, agent_name=agent_name, **classify_kwargs)
    if not prioritized:
        stats.setdefault("unclassified", 0)
        stats["unclassified"] += 1
        logger.debug(f"[{agent_name}] Step 4: Unclassified, returning")
        return
    if verbose_emitter:
        verbose_emitter.emit("strategy.finding.classified", {
            "type": finding.get("type"), "specialist": prioritized.specialist,
            "priority": round(prioritized.priority, 1),
        })
    logger.debug(f"[{agent_name}] Step 4 done: specialist={prioritized.specialist}, priority={prioritized.priority}")

    # 5. Distribute to specialist queue
    logger.debug(f"[{agent_name}] Step 5: Distribute to queue {prioritized.specialist}")
    success = await distribute_to_queue(
        prioritized,
        scan_context,
        scan_id,
        get_queues_dir_fn,
        queue_write_lock,
        stats,
        backpressure_retries,
        backpressure_delay,
        verbose_emitter,
        agent_name,
    )
    logger.debug(f"[{agent_name}] Step 5 done: success={success}")

    # 6. Emit work_queued event
    if success:
        logger.debug(f"[{agent_name}] Step 6: Emit work_queued event")
        dedup_metrics.record_distributed(prioritized.specialist)
        await emit_work_queued_event(prioritized, event_bus, emit_events, agent_name)
        logger.debug(f"[{agent_name}] Step 6 done")


async def process_batch_items(  # I/O
    batch: List[Dict[str, Any]],
    scan_context: str,
    dedup_cache: DeduplicationCache,
    stats: Dict[str, Any],
    scan_id: Optional[int],
    get_queues_dir_fn,
    queue_write_lock: asyncio.Lock,
    event_bus,
    fp_threshold: float = 0.3,
    backpressure_retries: int = 3,
    backpressure_delay: float = 1.0,
    emit_events: bool = True,
    verbose_emitter=None,
    agent_name: str = "ThinkingAgent",
    **classify_kwargs,
) -> None:
    """
    Process a batch of findings through the pipeline.

    Filters, deduplicates, classifies, prioritizes, sorts by priority,
    and distributes to specialist queues.

    Args:
        batch: List of finding dictionaries
        scan_context: Default scan context
        dedup_cache: DeduplicationCache instance
        stats: Statistics dict (mutated)
        scan_id: Optional scan ID for DB
        get_queues_dir_fn: Callable returning wet dir path
        queue_write_lock: Lock for file writes
        event_bus: Event bus instance
        fp_threshold: False positive threshold
        backpressure_retries: Retries on full queue
        backpressure_delay: Base delay
        emit_events: Whether to emit events
        verbose_emitter: Optional verbose emitter
        agent_name: Name for logging
        **classify_kwargs: Passed to classify_finding
    """
    if not batch:
        return

    logger.info(f"[{agent_name}] Processing batch of {len(batch)} findings")

    prioritized_batch: List[PrioritizedFinding] = []

    for finding in batch:
        item_scan_context = finding.pop("_scan_context", scan_context)

        specialist = classify_finding(finding, stats, agent_name=agent_name, **classify_kwargs) or "unknown"
        dedup_metrics.record_received(specialist)

        # FP filter
        fp_confidence = finding.get("fp_confidence", 0.5)
        skeptical_score = normalize_skeptical_score(finding.get("skeptical_score", 5))

        bypass = should_bypass_fp_filter(specialist, fp_confidence, skeptical_score, finding)

        if not bypass and fp_confidence < fp_threshold:
            stats["fp_filtered"] += 1
            dedup_metrics.record_fp_filtered()
            continue

        # Dedup check (auto-dispatched findings bypass)
        if not finding.get("_auto_dispatched"):
            is_duplicate, key = await dedup_cache.check_and_add(finding, item_scan_context)
            if is_duplicate:
                stats["duplicates_filtered"] += 1
                dedup_metrics.record_duplicate(specialist, key)
                continue

        # Classify and prioritize
        prioritized = classify_and_prioritize(
            finding, item_scan_context, stats, agent_name=agent_name, **classify_kwargs
        )
        if prioritized:
            prioritized_batch.append(prioritized)
        else:
            stats.setdefault("unclassified", 0)
            stats["unclassified"] += 1

    # Sort by priority (highest first)
    prioritized_batch.sort(key=lambda p: p.priority, reverse=True)

    # Distribute all in batch
    for prioritized in prioritized_batch:
        success = await distribute_to_queue(
            prioritized,
            scan_context,
            scan_id,
            get_queues_dir_fn,
            queue_write_lock,
            stats,
            backpressure_retries,
            backpressure_delay,
            verbose_emitter,
            agent_name,
        )
        if success:
            dedup_metrics.record_distributed(prioritized.specialist)
            await emit_work_queued_event(prioritized, event_bus, emit_events, agent_name)

    logger.info(f"[{agent_name}] Batch complete: {len(prioritized_batch)} distributed")
