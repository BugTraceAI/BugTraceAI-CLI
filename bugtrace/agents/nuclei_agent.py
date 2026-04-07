"""
Nuclei Agent - Backward compatibility shim.

All logic has been moved to the bugtrace.agents.nuclei subpackage.
This file re-exports NucleiAgent and KNOWN_VULNERABLE_JS for backward compatibility.
"""

from bugtrace.agents.nuclei.agent import NucleiAgent
from bugtrace.agents.nuclei.core import KNOWN_VULNERABLE_JS, load_vulnerable_js_libs

# Keep the module-level function available for any code that calls it
_load_vulnerable_js_libs = load_vulnerable_js_libs

__all__ = ["NucleiAgent", "KNOWN_VULNERABLE_JS"]
