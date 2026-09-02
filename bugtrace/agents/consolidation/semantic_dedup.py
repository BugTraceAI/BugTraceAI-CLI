"""PURE semantic near-dup collapse for prioritised findings.

Ported from the original thinking_consolidation_agent monolith, rewritten as
pure functions (no agent ``self``, no I/O). Embeddings are injected as
precomputed vectors so this module stays testable offline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from bugtrace.agents.consolidation.core import PrioritizedFinding
from bugtrace.core.semantic import cosine


def finding_strength(pf: PrioritizedFinding) -> Tuple[int, float, float]:
    """Rank for merge survival: validated > fp_confidence > priority (PURE)."""
    f = pf.finding
    validated = 1 if (f.get("validated") or f.get("probe_validated")) else 0
    try:
        fp_conf = float(f.get("fp_confidence", 0.5) or 0.5)
    except (TypeError, ValueError):
        fp_conf = 0.5
    return (validated, fp_conf, float(pf.priority))


def semantic_dedup_prioritized(
    batch: Sequence[PrioritizedFinding],
    vectors: Mapping[int, Sequence[float]],
    threshold: float,
) -> Tuple[List[PrioritizedFinding], int]:
    """Collapse near-duplicates within one specialist using cosine similarity.

    PURE: no embeddings I/O. Caller supplies ``vectors`` keyed by batch index.

    Rules (from original):
    - Never merge across specialists.
    - Always keep the stronger finding (finding_strength).
    - Empty / single-item batches pass through.

    Returns:
        (kept_batch, dropped_count)
    """
    if len(batch) < 2:
        return list(batch), 0

    dropped: set = set()
    n = len(batch)
    for i in range(n):
        if i in dropped or i not in vectors:
            continue
        for j in range(i + 1, n):
            if j in dropped or j not in vectors:
                continue
            if batch[i].specialist != batch[j].specialist:
                continue
            sim = cosine(vectors[i], vectors[j])
            if sim < threshold:
                continue
            if finding_strength(batch[i]) >= finding_strength(batch[j]):
                weaker, _stronger = j, i
            else:
                weaker, _stronger = i, j
            dropped.add(weaker)
            if weaker == i:
                break

    if not dropped:
        return list(batch), 0
    kept = [pf for idx, pf in enumerate(batch) if idx not in dropped]
    return kept, len(dropped)


def encode_prioritized_vectors(
    batch: Sequence[PrioritizedFinding],
    encode_query,
    build_text,
) -> Dict[int, Any]:
    """I/O helper: encode each finding via injected encode/build callables.

    Kept separate from the pure merge so tests can skip real embeddings.
    ``encode_query(text) -> vector|None``, ``build_text(finding) -> str|None``.
    """
    vectors: Dict[int, Any] = {}
    for idx, pf in enumerate(batch):
        text = build_text(pf.finding)
        if not text:
            continue
        vec = encode_query(text)
        if vec is not None:
            vectors[idx] = vec
    return vectors


def apply_semantic_dedup_batch(
    batch: List[PrioritizedFinding],
    *,
    enabled: bool,
    threshold: float,
    is_real_model: bool,
    encode_query,
    build_text,
    stats: Optional[Dict[str, Any]] = None,
    log=None,
) -> List[PrioritizedFinding]:
    """Orchestrate pure merge with injected embedding I/O (thin shell).

    Fail-open: any error returns the input batch unchanged.
    """
    if not enabled or len(batch) < 2 or not is_real_model:
        return batch
    try:
        vectors = encode_prioritized_vectors(batch, encode_query, build_text)
        kept, dropped = semantic_dedup_prioritized(batch, vectors, threshold)
        if dropped and stats is not None:
            stats["semantic_duplicates_filtered"] = (
                stats.get("semantic_duplicates_filtered", 0) + dropped
            )
        if dropped and log is not None:
            log(f"Semantic dedup: collapsed {dropped} near-duplicate(s)")
        return kept
    except Exception as e:
        if log is not None:
            log(f"Semantic dedup failed, using exact-key result: {e}")
        return batch
