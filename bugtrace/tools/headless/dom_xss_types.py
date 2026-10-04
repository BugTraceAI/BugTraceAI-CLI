"""DOM XSS types and sink-param lists."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List


_PARAMS_FILE = Path(__file__).resolve().parent.parent.parent / "payloads" / "dom_xss_params.json"
_dom_xss_params = json.loads(_PARAMS_FILE.read_text())
DOM_REDIRECT_PARAMS: List[str] = _dom_xss_params["redirect_params"]
DOM_SEARCH_PARAMS: List[str] = _dom_xss_params["search_params"]
DOM_SINK_PARAMS: List[str] = DOM_REDIRECT_PARAMS + DOM_SEARCH_PARAMS


@dataclass
class DOMXSSFinding:
    """Represents a confirmed DOM XSS vulnerability."""
    url: str
    payload: str
    sink: str  # innerHTML, eval, document.write, etc.
    source: str  # location.hash, location.search, document.referrer, etc.
    evidence: str
    severity: str = "HIGH"
