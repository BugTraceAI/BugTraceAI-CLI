"""
Consolidation Prompts

PURE functions for LLM prompt building and embeddings-based
classification for consolidation analysis.

Extracted from thinking_consolidation_agent.py for modularity.
"""

from typing import Dict, List, Any, Optional, Tuple
from loguru import logger

from bugtrace.agents.consolidation.core import SPECIALIST_DESCRIPTIONS


def build_finding_semantic_text(finding: Dict[str, Any]) -> Optional[str]:  # PURE
    """
    Build semantic text representation of a finding for embeddings.

    Creates a rich text string from finding fields suitable for
    encoding into an embedding vector.

    Args:
        finding: Finding dictionary with type, parameter, payload, etc.

    Returns:
        Semantic text string, or None if finding has no usable text
    """
    text_parts = []

    vuln_type = finding.get("type", "")
    if vuln_type:
        text_parts.append(f"Vulnerability type: {vuln_type}")

    parameter = finding.get("parameter", "")
    if parameter:
        text_parts.append(f"Parameter: {parameter}")

    payload = finding.get("payload", "")
    if payload:
        payload_str = str(payload)[:200]
        text_parts.append(f"Payload: {payload_str}")

    details = finding.get("details", "")
    if details:
        details_str = str(details)[:300]
        text_parts.append(f"Details: {details_str}")

    if not text_parts:
        return None

    return " | ".join(text_parts)


def classify_with_embeddings(
    finding: Dict[str, Any],
    embedding_manager: Any,
    specialist_embeddings: Dict[str, Any],
    log_confidence: bool = False,
    agent_name: str = "ThinkingAgent",
) -> Optional[Tuple[str, float]]:  # PURE (except embedding encode call)
    """
    Classify finding using semantic similarity with specialist descriptions.

    Process:
    1. Create semantic text from finding
    2. Encode to embedding vector
    3. Compare cosine similarity with all specialist embeddings
    4. Return best match with confidence score

    Args:
        finding: Finding dictionary
        embedding_manager: EmbeddingManager instance with encode_query method
        specialist_embeddings: Dict mapping specialist name to embedding vector
        log_confidence: Whether to log top-3 candidates
        agent_name: Name for logging

    Returns:
        (specialist_name, confidence_score) tuple, or None if unavailable
    """
    if not embedding_manager or not specialist_embeddings:
        return None

    text = build_finding_semantic_text(finding)
    if not text:
        logger.debug(f"[{agent_name}] Embeddings: No text to encode (empty finding)")
        return None

    try:
        finding_embedding = embedding_manager.encode_query(text)
    except Exception as e:
        logger.error(f"[{agent_name}] Failed to encode finding: {e}")
        return None

    import numpy as np

    similarities = {}
    for specialist, spec_embedding in specialist_embeddings.items():
        similarity = np.dot(finding_embedding, spec_embedding) / (
            np.linalg.norm(finding_embedding) * np.linalg.norm(spec_embedding)
        )
        similarities[specialist] = float(similarity)

    if not similarities:
        return None

    best_specialist = max(similarities, key=similarities.get)
    best_confidence = similarities[best_specialist]

    if log_confidence:
        vuln_type = finding.get("type", "")
        top_3 = sorted(similarities.items(), key=lambda x: x[1], reverse=True)[:3]
        top_3_str = ", ".join([f"{s}={c:.3f}" for s, c in top_3])
        logger.debug(
            f"[{agent_name}] Embeddings similarity: type='{vuln_type}' "
            f"top_3=[{top_3_str}]"
        )

    return (best_specialist, best_confidence)


def initialize_embeddings(
    use_embeddings: bool,
    agent_name: str = "ThinkingAgent",
) -> Tuple[Optional[Any], Dict[str, Any], bool]:  # I/O (loads model)
    """
    Lazy load embeddings model and pre-compute specialist descriptions.

    Args:
        use_embeddings: Whether embeddings classification is enabled
        agent_name: Name for logging

    Returns:
        Tuple of (embedding_manager, specialist_embeddings_dict, success_bool)
    """
    if not use_embeddings:
        return None, {}, False

    try:
        from bugtrace.core.embeddings import EmbeddingManager, MockEmbeddingModel

        embedding_manager = EmbeddingManager.get_instance()
        logger.info(f"[{agent_name}] Loading embeddings model...")

        if isinstance(embedding_manager._model, MockEmbeddingModel):
            logger.warning(
                f"[{agent_name}] Offline mode detected (MockEmbeddingModel), "
                f"disabling embeddings classification"
            )
            return None, {}, False

        specialist_embeddings = {}
        for specialist, description in SPECIALIST_DESCRIPTIONS.items():
            embedding = embedding_manager.encode_query(description)
            specialist_embeddings[specialist] = embedding

        logger.info(
            f"[{agent_name}] Embeddings initialized: {len(specialist_embeddings)} "
            f"specialists, {embedding_manager.get_embedding_dimension()}D vectors"
        )
        return embedding_manager, specialist_embeddings, True

    except Exception as e:
        logger.error(f"[{agent_name}] Embeddings initialization failed: {e}")
        logger.warning(f"[{agent_name}] Falling back to keyword-only classification")
        return None, {}, False
