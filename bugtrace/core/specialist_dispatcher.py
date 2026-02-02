"""
Specialist Dispatcher - Simple dispatcher for specialist agents.

Responsibilities:
- Check which queues have work
- Start only necessary specialists
- Return dispatch summary
"""
import asyncio
from typing import Dict, List, Any
from bugtrace.core.queue import queue_manager
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)


async def dispatch_specialists(
    specialist_agents: Dict[str, Any],
    scan_context: str,
    max_concurrent: int
) -> Dict[str, Any]:
    """
    Dispatcher with concurrency control: Check queues → Wake specialists → Wait for completion.

    Args:
        specialist_agents: Map of queue_name -> agent instance
            Example: {"sqli": SQLiAgent(), "xss": XSSAgent(), ...}
        scan_context: Scan context to pass to specialists
        max_concurrent: Max specialists executing simultaneously
                       (Loaded from bugtraceaicli.conf [PARALLELIZATION] MAX_CONCURRENT_SPECIALISTS)

    Returns:
        Dict with dispatch summary:
        {
            "specialists_dispatched": 3,
            "activated": ["sqli", "xss", "xxe"],
            "skipped": ["csti", "lfi", ...]
        }
    """
    specialists_to_run = []
    activated = []
    skipped = []

    logger.info(f"[Dispatcher] Checking {len(specialist_agents)} queues for work...")

    # 1. Identify specialists with work
    for queue_name, agent in specialist_agents.items():
        try:
            queue = queue_manager.get_queue(queue_name)
            depth = queue.depth() if hasattr(queue, 'depth') else 0

            if depth > 0:
                logger.info(f"[Dispatcher] Queue '{queue_name}': {depth} items → Queued for execution")
                specialists_to_run.append((queue_name, agent))
                activated.append(queue_name)
            else:
                logger.debug(f"[Dispatcher] Queue '{queue_name}': empty → Skip")
                skipped.append(queue_name)

        except Exception as e:
            logger.warning(f"[Dispatcher] Failed to check queue '{queue_name}': {e}")
            skipped.append(queue_name)

    if not specialists_to_run:
        logger.warning("[Dispatcher] No work found - no specialists dispatched")
        return {
            "specialists_dispatched": 0,
            "activated": [],
            "skipped": skipped
        }

    # 2. Execute with concurrency control (semaphore)
    semaphore = asyncio.Semaphore(max_concurrent)

    async def run_with_semaphore(queue_name: str, agent: Any):
        """Run specialist with semaphore to limit concurrency."""
        async with semaphore:  # Blocks if max_concurrent reached
            logger.info(f"[Dispatcher] Starting specialist: {queue_name}")
            await agent.start_queue_consumer(scan_context)
            logger.info(f"[Dispatcher] Completed specialist: {queue_name}")

    # 3. Launch all (but semaphore controls simultaneous execution)
    tasks = [
        run_with_semaphore(queue_name, agent)
        for queue_name, agent in specialists_to_run
    ]

    logger.info(
        f"[Dispatcher] Dispatching {len(specialists_to_run)} specialist(s) "
        f"with max_concurrent={max_concurrent}: {', '.join(activated)}"
    )

    await asyncio.gather(*tasks)

    logger.info(f"[Dispatcher] All {len(specialists_to_run)} specialist(s) completed")

    return {
        "specialists_dispatched": len(specialists_to_run),
        "activated": activated,
        "skipped": skipped
    }
