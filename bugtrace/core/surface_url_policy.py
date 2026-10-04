"""Pure URL surface fingerprint / dedup policy (Phase 3 residual).

No I/O, logging, settings, or TeamOrchestrator. Path/query shape decisions only.
Shell mixins adapt and log.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

PATH_NUMERIC_RE = re.compile(r"^[0-9]+$")
PATH_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
PATH_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)

# Pattern dedup uses :id / :uuid placeholders (historical report log shape).
_PATTERN_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)


def canonicalize_path(path: str) -> str:
    """Replace dynamic path segments with placeholders.

    Conservative — only pure numeric, UUID, and long hex segments.
    Alphabetic / short mixed segments stay as-is.
    """
    segments = path.split("/")
    canonical: List[str] = []
    for seg in segments:
        if not seg:
            canonical.append(seg)
        elif PATH_NUMERIC_RE.match(seg):
            canonical.append("{N}")
        elif PATH_UUID_RE.match(seg):
            canonical.append("{UUID}")
        elif PATH_HEX_RE.match(seg):
            canonical.append("{HEX}")
        else:
            canonical.append(seg)
    return "/".join(canonical)


def url_fingerprint(url: str) -> str:
    """scheme+host+canonical_path+sorted_param_names (values ignored)."""
    parsed = urlparse(url)
    canonical = canonicalize_path(parsed.path)
    param_names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
    return f"{parsed.scheme}://{parsed.netloc}{canonical}?{'&'.join(param_names)}"


def superset_param_dedup(urls: Sequence[str]) -> Tuple[List[str], Dict[str, dict]]:
    """Collapse URLs where one param-name set is a superset of another on same path.

    Groups by scheme+host+canonical_path. Within a group, subset param sets drop.
    Returns (deduplicated_urls, superset_log).
    """
    groups: dict[str, list[tuple[str, frozenset[str]]]] = defaultdict(list)
    for url in urls:
        parsed = urlparse(url)
        canonical = canonicalize_path(parsed.path)
        base_key = f"{parsed.scheme}://{parsed.netloc}{canonical}"
        param_names = frozenset(
            parse_qs(parsed.query, keep_blank_values=True).keys()
        )
        groups[base_key].append((url, param_names))

    result: List[str] = []
    superset_log: Dict[str, dict] = {}

    for base_key, url_entries in groups.items():
        if len(url_entries) == 1:
            result.append(url_entries[0][0])
            continue

        url_entries.sort(key=lambda x: len(x[1]), reverse=True)
        kept: list[tuple[str, frozenset[str]]] = []
        collapsed: list[str] = []

        for url, params in url_entries:
            is_subset = False
            for _kept_url, kept_params in kept:
                if params <= kept_params:
                    is_subset = True
                    collapsed.append(url)
                    break
            if not is_subset:
                kept.append((url, params))

        for url, _ in kept:
            result.append(url)

        if collapsed:
            superset_log[base_key] = {
                "kept": [u for u, _ in kept],
                "collapsed": collapsed,
                "collapsed_count": len(collapsed),
            }

    return result, superset_log


def url_pattern_key(url: str) -> str:
    """Pattern key for path-shape dedup (:id / :uuid + sorted param names)."""
    parsed = urlparse(url)
    segments = parsed.path.rstrip("/").split("/")
    normalized: List[str] = []
    for seg in segments:
        if seg.isdigit():
            normalized.append(":id")
        elif _PATTERN_UUID_RE.match(seg):
            normalized.append(":uuid")
        else:
            normalized.append(seg)
    params = sorted(parse_qs(parsed.query).keys())
    path_part = "/".join(normalized)
    return path_part + "?" + "&".join(params) if params else path_part


def dedup_url_patterns(urls: Sequence[str]) -> Tuple[List[str], int]:
    """Keep first URL per path pattern. Returns (deduped, removed_count)."""
    seen: dict[str, str] = {}
    deduped: List[str] = []
    for url in urls:
        pattern = url_pattern_key(url)
        if pattern not in seen:
            seen[pattern] = url
            deduped.append(url)
    removed = len(urls) - len(deduped)
    return deduped, removed


__all__ = [
    "PATH_NUMERIC_RE",
    "PATH_UUID_RE",
    "PATH_HEX_RE",
    "canonicalize_path",
    "url_fingerprint",
    "superset_param_dedup",
    "url_pattern_key",
    "dedup_url_patterns",
]
