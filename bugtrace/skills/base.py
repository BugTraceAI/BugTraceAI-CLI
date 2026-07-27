"""
BaseSkill - Foundation class for all URLMasterAgent skills.

Skills are modular wrappers around vulnerability testing functionality.
"""

from typing import Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from bugtrace.agents.url_master import URLMasterAgent


class BaseSkill:
    """Base class for all skills.
    
    Skills encapsulate specific vulnerability testing or reconnaissance 
    capabilities. They maintain a reference to their parent URLMasterAgent
    for access to thread context, findings, and shared utilities.
    
    Attributes:
        description: Human-readable description of what this skill does.
        master: Reference to the parent URLMasterAgent instance.
    """
    
    description = "Base skill"
    
    def __init__(self, master: "URLMasterAgent"):
        """Initialize skill with reference to parent agent.
        
        Args:
            master: The URLMasterAgent that owns this skill.
        """
        self.master = master
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the skill against a target URL.
        
        Args:
            url: The target URL to test.
            params: Additional parameters for skill execution.
        
        Returns:
            Dict containing execution results with at least:
                - success: bool indicating if skill ran without errors
                - findings: list of vulnerability findings (if any)
                - error: error message (if success is False)
        
        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement execute()")
