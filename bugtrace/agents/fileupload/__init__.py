"""
File Upload Agent Module

Detects unrestricted file upload / RCE vulnerabilities through
autonomous discovery and LLM-guided bypass testing.

Modules:
    - core: PURE functions for upload strategy extraction, finding construction,
            form metadata parsing
    - testing: I/O functions for upload form discovery, multipart upload,
               execution validation, LLM strategy calls
    - agent: Thin orchestrator (FileUploadAgent class)

Usage:
    from bugtrace.agents.fileupload import FileUploadAgent

For backward compatibility:
    from bugtrace.agents.fileupload_agent import FileUploadAgent
"""

from bugtrace.agents.fileupload.core import (
    get_upload_strategy,
    create_upload_finding,
    extract_form_metadata,
    build_llm_prompt,
)

from bugtrace.agents.fileupload.testing import (
    discover_upload_forms,
    upload_file,
    validate_execution,
    llm_get_strategy,
    test_form,
)

from bugtrace.agents.fileupload.agent import FileUploadAgent

__all__ = [
    # Main class
    "FileUploadAgent",
    # Core (PURE)
    "get_upload_strategy",
    "create_upload_finding",
    "extract_form_metadata",
    "build_llm_prompt",
    # Testing (I/O)
    "discover_upload_forms",
    "upload_file",
    "validate_execution",
    "llm_get_strategy",
    "test_form",
]
