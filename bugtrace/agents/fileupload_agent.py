"""
File Upload Agent - Backward compatibility shim.

All logic has been moved to the bugtrace.agents.fileupload subpackage.
This file re-exports FileUploadAgent for backward compatibility.
"""

from bugtrace.agents.fileupload.agent import FileUploadAgent

__all__ = ["FileUploadAgent"]
