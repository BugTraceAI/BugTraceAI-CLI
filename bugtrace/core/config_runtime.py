"""Config runtime helpers (paths, hot-reload watcher) — extracted for size policy."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Any

from bugtrace.utils.logger import get_logger

logger = get_logger("core.config")

_config_watcher = None


def ensure_runtime_directories(root: Path | None = None) -> Path | None:
    """Create data/logs/reports/tmp under the active runtime root (if any)."""
    from bugtrace.core.config import settings

    target = root if root is not None else settings.RUNTIME_ROOT
    if target is None:
        return None
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    for sub in ("data", "logs", "reports", "tmp"):
        (target / sub).mkdir(exist_ok=True)
    return target


def apply_runtime_root(root: Path | str) -> Path:
    """Rebind writable runtime paths after import (pytest / smoke harnesses).

    Does not change BASE_DIR (package root / conf / provider presets).
    Resets the DatabaseManager singleton so the next get_instance uses the new
    data path. Rebinds file log handlers to RUNTIME_ROOT/logs.
    Call only from tests or hermetic harnesses.
    """
    from bugtrace.core.config import settings

    target = Path(root).expanduser().resolve()
    ensure_runtime_directories(target)
    settings.RUNTIME_ROOT = target
    # Absolute path fields win over relative joins; keep relative names under root.
    settings.LOG_DIR_PATH = "logs"
    settings.REPORT_DIR_PATH = "reports"
    os.environ["BUGTRACE_TEST_ROOT"] = str(target)
    try:
        from bugtrace.utils.logger import reconfigure_log_directory

        reconfigure_log_directory(settings.LOG_DIR)
    except Exception as exc:  # pragma: no cover - import-time edge
        logger.debug(f"Logger rebind deferred: {exc}")
    try:
        from bugtrace.core.database import DatabaseManager

        DatabaseManager.reset_instance()
    except Exception as exc:  # pragma: no cover - import-time edge
        logger.debug(f"DatabaseManager reset deferred: {exc}")
    return target


def start_config_watcher():
    """Start watching config file for changes (requires watchdog package)."""
    global _config_watcher
    from bugtrace.core.config import settings

    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class ConfigFileHandler(FileSystemEventHandler):
            def __init__(self, config_path, callback):
                self.config_path = str(config_path)
                self.callback = callback

            def on_modified(self, event):
                if event.src_path == self.config_path:
                    logger.info("Config file changed, reloading...")
                    self.callback()

        def reload_config():
            settings.load_from_conf()
            settings.log_config()
            logger.info("Configuration reloaded successfully")

        conf_path = settings.BASE_DIR / "bugtraceaicli.conf"
        observer = Observer()
        observer.schedule(
            ConfigFileHandler(conf_path, reload_config),
            path=str(settings.BASE_DIR),
            recursive=False
        )
        observer.start()
        _config_watcher = observer
        logger.info("Config file watcher started")
        return observer
    except ImportError:
        logger.debug("watchdog not installed, config hot-reload disabled")
        return None


def stop_config_watcher():
    """Stop the config file watcher."""
    global _config_watcher
    if _config_watcher:
        _config_watcher.stop()
        _config_watcher.join()
        _config_watcher = None
        logger.info("Config file watcher stopped")
