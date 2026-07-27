"""
Shared semantic helpers for finding-level embeddings work.

PURE functions only — this module holds no model or state. Single source of
truth for:
  - build_finding_semantic_text(finding) -> Optional[str]
  - cosine(a, b) -> float

Call sites reuse the already-loaded bge model via
`EmbeddingManager.get_instance()` (the model is warmed on every scan regardless
of flags), so a semantic pass costs encode-time only, not a second model load.

Used by the in-scan semantic dedup pass in `thinking_consolidation_agent`, and
available to the embeddings-classification path. Keeping the text builder and
the cosine in ONE place avoids the third-copy antipattern.
"""
from typing import Any, Dict, List, Optional, Sequence


def build_finding_semantic_text(finding: Dict[str, Any]) -> Optional[str]:  # PURE
    """Build a semantic text representation of a finding for embedding.

    Mirrors the fields used by `EmbeddingManager.encode_finding`
    (type | parameter | payload[:200] | details[:300] | Path:<url.path>) so the
    same finding embeds identically wherever it is encoded. Returns None when the
    finding carries no usable text (caller should skip it, never encode "").
    """
    text_parts: List[str] = []

    vuln_type = finding.get("type", "")
    if vuln_type:
        text_parts.append(f"Vulnerability type: {vuln_type}")

    parameter = finding.get("parameter", "")
    if parameter:
        text_parts.append(f"Parameter: {parameter}")

    payload = finding.get("payload", "")
    if payload:
        text_parts.append(f"Payload: {str(payload)[:200]}")

    details = finding.get("details", "")
    if details:
        text_parts.append(f"Details: {str(details)[:300]}")

    url = finding.get("url", "")
    if url:
        from urllib.parse import urlparse
        path = urlparse(url).path
        if path:
            text_parts.append(f"Path: {path}")

    if not text_parts:
        return None
    return " | ".join(text_parts)


def cosine(a: Sequence[float], b: Sequence[float]) -> float:  # PURE
    """Cosine similarity of two equal-length vectors.

    Returns 0.0 on degenerate input (zero-norm vector) instead of dividing by
    zero — a finding with a null embedding simply never matches.
    """
    import numpy as np

    va = np.asarray(a, dtype=float)
    vb = np.asarray(b, dtype=float)
    na = np.linalg.norm(va)
    nb = np.linalg.norm(vb)
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(np.dot(va, vb) / (na * nb))
