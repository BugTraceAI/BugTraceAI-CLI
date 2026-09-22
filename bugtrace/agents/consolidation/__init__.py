"""
Consolidation Agent Module

Evaluation phase coordinator for the v2.3 Pipeline.
Deduplicates findings, classifies by vulnerability type,
prioritizes by exploitation probability, and distributes
to specialist queues.

Modules:
    - core: PURE functions for classification, dedup, severity scoring
    - prompts: PURE functions for LLM prompt/embedding classification
    - processing: I/O layer for queue management and distribution
    - agent: Thin orchestrator (ThinkingConsolidationAgent)

Usage:
    from bugtrace.agents.consolidation import ThinkingConsolidationAgent

For backward compatibility:
    from bugtrace.agents.thinking_consolidation_agent import ThinkingConsolidationAgent
"""

from bugtrace.agents.consolidation.core import (
    VULN_TYPE_TO_SPECIALIST,
    SPECIALIST_DESCRIPTIONS,
    SEVERITY_PRIORITY,
    FindingRecord,
    PrioritizedFinding,
    DeduplicationCache,
    classify_finding,
    calculate_priority,
    classify_and_prioritize,
    normalize_parameter,
    make_dedup_key,
)

from bugtrace.agents.consolidation.prompts import (
    initialize_embeddings,
    classify_with_embeddings,
    build_finding_semantic_text,
)

from bugtrace.agents.consolidation.processing import (
    persist_queue_item,
    distribute_to_queue,
    emit_work_queued_event,
    process_finding,
    process_batch_items,
)

from bugtrace.agents.consolidation.agent import ThinkingConsolidationAgent

__all__ = [
    # Main class
    "ThinkingConsolidationAgent",
    # Core types and data
    "VULN_TYPE_TO_SPECIALIST",
    "SPECIALIST_DESCRIPTIONS",
    "SEVERITY_PRIORITY",
    "FindingRecord",
    "PrioritizedFinding",
    "DeduplicationCache",
    # Core pure functions
    "classify_finding",
    "calculate_priority",
    "classify_and_prioritize",
    "normalize_parameter",
    "make_dedup_key",
    # Embeddings
    "initialize_embeddings",
    "classify_with_embeddings",
    "build_finding_semantic_text",
    # Processing (I/O)
    "persist_queue_item",
    "distribute_to_queue",
    "emit_work_queued_event",
    "process_finding",
    "process_batch_items",
]
