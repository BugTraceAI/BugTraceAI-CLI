"""Pure path resolvers for the bugtrace package tree.

After dual peels moved code from ``bugtrace/core/team.py`` into
``bugtrace/core/team/*.py``, naive ``Path(__file__).parent.parent / "data"``
points at ``bugtrace/core/data`` (missing) instead of ``bugtrace/data``.

Always resolve data/config via the installed ``bugtrace`` package root.
"""

from __future__ import annotations

from pathlib import Path


def bugtrace_package_root() -> Path:
    """Return the ``bugtrace/`` package directory (contains ``data/``, ``agents/``)."""
    import bugtrace

    return Path(bugtrace.__file__).resolve().parent


def bugtrace_data_dir() -> Path:
    """``bugtrace/data`` — wordlists, nuclei routing, provider presets, etc."""
    return bugtrace_package_root() / "data"


def bugtrace_data_file(*parts: str) -> Path:
    """Join one or more relative path parts under ``bugtrace/data``."""
    return bugtrace_data_dir().joinpath(*parts)
