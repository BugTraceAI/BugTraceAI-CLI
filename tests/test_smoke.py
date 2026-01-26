import pytest
import asyncio
from bugtrace.core.config import settings
from bugtrace.core.team import TeamOrchestrator
from bugtrace.memory.manager import MemoryManager
from bugtrace.core.chain_reactor import chain_reactor
from bugtrace.schemas.models import VulnType

@pytest.mark.asyncio
async def test_config_loading():
    """Verify settings load correctly."""
    assert settings.APP_NAME == "BugtraceAI-CLI"
    assert settings.SAFE_MODE is False
    assert settings.LOG_DIR is not None

@pytest.mark.asyncio
async def test_memory_manager():
    """Verify Memory Manager basics."""
    mem = MemoryManager()
    # Test Graph
    mem.add_node("TestNode", "unit_test_node", {"test": True})
    assert mem.graph.has_node("TestNode:unit_test_node")
    
    # Test Vector Schema (Mocking actual embedding to avoid model load time in test?)
    # For smoke test, we just check if table init didn't crash
    if mem.obs_table:
        pass # Good

@pytest.mark.asyncio
async def test_orchestrator_init():
    """Verify TeamOrchestrator initializes without crash."""
    orch = TeamOrchestrator("http://example.com")
    assert orch.target == "http://example.com"
    assert len(orch.agents) == 0 # Agents init on start()

@pytest.mark.asyncio
async def test_chain_reactor_types():
    """Verify ChainReactor and Enum compatibility."""
    assert VulnType.XSS == "XSS"
    assert VulnType.SQLI == "SQLI"
    # Just ensure reactor singleton exists
    assert chain_reactor is not None
