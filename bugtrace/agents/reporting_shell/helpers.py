"""Small pure helpers for reporting shell mixins."""
from __future__ import annotations

import re

def _normalize_markdown_document(content: str) -> str:
    """Remove an accidental outer LLM fence while preserving inner code blocks."""
    lines = content.strip().splitlines()
    if not lines or not re.fullmatch(r"```(?:markdown|md|plaintext|text)?[ \t]*", lines[0], re.IGNORECASE):
        return content

    closing_index = next(
        (index for index in range(len(lines) - 1, 0, -1) if re.fullmatch(r"```[ \t]*", lines[index])),
        -1,
    )
    if closing_index < 0:
        return content

    wrapped_body = "\n".join(lines[1:closing_index])
    if not re.search(
        r"(^|\n)(?:#{1,6}\s+\S|(?:[-*+]|\d+\.)\s+\S|>\s+\S|\|.+\|\s*$)|\*\*[^*\n]+\*\*",
        wrapped_body,
    ):
        return content

    return "\n".join(lines[1:closing_index] + lines[closing_index + 1:]).strip()

