from rich.logging import RichHandler
import contextvars
import logging
import sys
import os
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime

# ContextVar for correlation_id — set per-request by API middleware
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")


def set_correlation_id(cid: str) -> None:
    """Set the correlation_id for the current async/thread context."""
    correlation_id_var.set(cid)


def get_correlation_id() -> str:
    """Return the current correlation_id (empty string if unset)."""
    return correlation_id_var.get("")

_LOG_FILE_NAMES = ("bugtrace.jsonl", "execution.log", "errors.log")


def _resolve_log_dir_from_env() -> str:
    """Prefer hermetic runtime root when BUGTRACE_TEST_ROOT is set.

    This runs before settings may be fully applied, so env is the source of
    truth for early imports during pytest bootstrap.
    """
    from bugtrace.core.runtime_paths import resolve_log_dir

    path = str(resolve_log_dir())
    os.makedirs(path, exist_ok=True)
    return path


LOG_DIR = _resolve_log_dir_from_env()


def reconfigure_log_directory(log_dir: str | os.PathLike[str]) -> str:
    """Point module LOG_DIR and existing RotatingFileHandlers at a new directory.

    Called from apply_runtime_root so hermetic rebinds do not keep writing into
    a discarded temp root or the worktree.
    """
    global LOG_DIR
    new_dir = os.path.abspath(str(log_dir))
    os.makedirs(new_dir, exist_ok=True)
    old_dir = os.path.abspath(LOG_DIR)
    LOG_DIR = new_dir
    if old_dir == new_dir:
        return new_dir

    manager = logging.Logger.manager.loggerDict
    loggers: list[logging.Logger] = [logging.getLogger()]
    for name, obj in list(manager.items()):
        if isinstance(obj, logging.Logger):
            loggers.append(obj)
        elif isinstance(name, str):
            loggers.append(logging.getLogger(name))

    for lg in loggers:
        for handler in list(lg.handlers):
            if not isinstance(handler, RotatingFileHandler):
                continue
            base = os.path.basename(handler.baseFilename)
            if base not in _LOG_FILE_NAMES:
                continue
            # Rebuild an equivalent rotating handler under the new directory.
            level = handler.level
            formatter = handler.formatter
            max_bytes = getattr(handler, "maxBytes", 5 * 1024 * 1024)
            backup_count = getattr(handler, "backupCount", 5)
            try:
                handler.close()
            except Exception:
                pass
            lg.removeHandler(handler)
            replacement = RotatingFileHandler(
                os.path.join(new_dir, base),
                maxBytes=max_bytes,
                backupCount=backup_count,
            )
            replacement.setLevel(level)
            if formatter is not None:
                replacement.setFormatter(formatter)
            lg.addHandler(replacement)
    return new_dir


class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings for structured logging.
    """
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "correlation_id": correlation_id_var.get(""),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "file": record.filename,
            "line": record.lineno
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def get_logger(name: str):
    """
    Configures and returns a logger with console and file handlers.
    """
    logger = logging.getLogger(name)
    
    # If logger already has handlers, return it to avoid duplicates
    if logger.handlers:
        return logger
        
    logger.setLevel(logging.INFO)

    # 1. Console Handler (Rich)
    console_handler = RichHandler(rich_tracebacks=True, show_time=False, show_level=True)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    # 2. File Handler (JSONL) - Rotating
    # 5MB max size, keep 5 backup files
    json_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "bugtrace.jsonl"), 
        maxBytes=5*1024*1024, 
        backupCount=5
    )
    json_handler.setLevel(logging.INFO)
    json_handler.setFormatter(JSONFormatter())
    logger.addHandler(json_handler)

    # 3. Execution File Handler (Plain Text) - INFO and above
    execution_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "execution.log"),
        maxBytes=10*1024*1024,
        backupCount=5
    )
    execution_handler.setLevel(logging.INFO)
    execution_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(execution_handler)

    # 4. Error File Handler (Plain Text) - Errors only
    error_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "errors.log"),
        maxBytes=5*1024*1024,
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(error_handler)

    return logger

# Default root logger
logger = get_logger("bugtraceai")
