from pydantic import BaseModel, Field, HttpUrl
from typing import Dict, List, Optional, Any, Union
from enum import Enum

class MutationStrategy(str, Enum):
    PAYLOAD_INJECTION = "PAYLOAD_INJECTION"
    BYPASS_WAF = "BYPASS_WAF"
    LOGIC_INVERSION = "LOGIC_INVERSION"
    HEADER_MANIPULATION = "HEADER_MANIPULATION"
    METHOD_TAMPERING = "METHOD_TAMPERING"
    # Extended attack vectors
    SSTI_INJECTION = "SSTI_INJECTION"
    CMD_INJECTION = "CMD_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"

class FeedbackStatus(str, Enum):
    SUCCESS = "SUCCESS"  # Validated/Exploited
    BLOCKED = "BLOCKED"  # WAF/403
    FAILED = "FAILED"    # No effect
    ERROR = "ERROR"      # Network/System error
    REFLECTED = "REFLECTED" # Payload echoed back but not necessarily exploited

class AgentFeedback(BaseModel):
    strategy: MutationStrategy
    status: FeedbackStatus
    payload_used: str
    response_code: int
    response_snippet: str
    notes: Optional[str] = None

class MutableRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, str] = Field(default_factory=dict)
    data: Optional[Union[Dict[str, Any], str]] = None
    json_payload: Optional[Dict[str, Any]] = None
    cookies: Dict[str, str] = Field(default_factory=dict)
    
    def to_curl(self) -> str:
        # Helper for debugging
        header_str = " ".join([f"-H '{k}: {v}'" for k, v in self.headers.items()])
        return f"curl -X {self.method} '{self.url}' {header_str}"
