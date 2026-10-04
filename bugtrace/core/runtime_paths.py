"""Pure path resolution for package root and writable runtime roots.

This module is the Phase 2 foundation for configuration path ownership:
explicit inputs (environment mapping + optional anchors) → Path values.
It performs no logging, dotenv loading, database I/O, or network I/O.

Callers:
- ``bugtrace.core.config`` uses these resolvers for Settings.BASE_DIR /
  RUNTIME_ROOT defaults.
- ``bugtrace.utils.logger`` uses ``resolve_runtime_root`` for early log dir
  placement under hermetic tests.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


def truthy_env(name: str, env: Mapping[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return str(source.get(name, "")).strip().lower() in ("1", "true", "yes", "on")


def test_mode_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Hermetic/offline test mode: skip .env side effects and live watchers."""
    return truthy_env("BUGTRACE_TEST_MODE", env)


def env_path(name: str, env: Mapping[str, str] | None = None) -> Path | None:
    source = os.environ if env is None else env
    raw = str(source.get(name, "")).strip()
    if not raw:
        return None
    return Path(raw).expanduser().resolve()


def resolve_package_base_dir(
    *,
    env: Mapping[str, str] | None = None,
    anchor_file: Path | str | None = None,
) -> Path:
    """Package / project root used for conf files and packaged data.

    BUGTRACE_BASE_DIR relocates the entire project root (rare; operators).
    When unset, defaults to three parents above ``anchor_file`` (config.py).
    """
    override = env_path("BUGTRACE_BASE_DIR", env)
    if override is not None:
        return override
    if anchor_file is None:
        # bugtrace/core/runtime_paths.py → core → bugtrace → repo root
        anchor_file = Path(__file__)
    return Path(anchor_file).resolve().parent.parent.parent


def resolve_runtime_root(env: Mapping[str, str] | None = None) -> Path | None:
    """Writable runtime root for data/logs/reports (hermetic tests).

    BUGTRACE_TEST_ROOT is preferred; BUGTRACE_RUNTIME_ROOT is an alias.
    """
    return env_path("BUGTRACE_TEST_ROOT", env) or env_path("BUGTRACE_RUNTIME_ROOT", env)


def resolve_log_dir(
    *,
    env: Mapping[str, str] | None = None,
    default: str = "logs",
) -> Path:
    """Directory for process log files.

    Under a runtime root → ``<runtime>/logs``; otherwise CWD-relative ``logs``.
    """
    root = resolve_runtime_root(env)
    if root is not None:
        return root / "logs"
    return Path(default)


def data_dir_for(base_or_runtime: Path) -> Path:
    return Path(base_or_runtime) / "data"


def reports_dir_for(base_or_runtime: Path) -> Path:
    return Path(base_or_runtime) / "reports"
