from rich.logging import RichHandler
import logging
import sys
import os
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Define log directory
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings for structured logging.
    """
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message":record.getMessage(),
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
