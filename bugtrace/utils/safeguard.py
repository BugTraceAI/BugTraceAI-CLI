import asyncio
import functools
from typing import Any, Callable, Dict, Optional, Coroutine
from loguru import logger

async def run_tool_safely(
    tool_name: str,
    coro_func: Callable[..., Coroutine[Any, Any, Any]],
    *args,
    timeout: float = 30.0,
    default_return: Optional[Any] = None,
    **kwargs
) -> Any:
    """
    Executes an async tool function with a strict safety wrapper.
    
    Features:
    - Enforced Timeout: Prevents infinite hangs.
    - Exception Isolation: Catches ALL exceptions so the agent doesn't crash.
    - Resource Cleanup: (Handled by asyncio cancellation).
    
    Args:
        tool_name: Name of the tool for logging (e.g., 'Browser', 'SQLMap').
        coro_func: The async function to execute.
        *args, **kwargs: Arguments for the function.
        timeout: Max execution time in seconds.
        default_return: Value to return on failure (default: None).
        
    Returns:
        The result of the coroutine, or default_return if failed.
    """
    try:
        # Create the coroutine
        coro = coro_func(*args, **kwargs)
        
        # Execute with timeout
        return await asyncio.wait_for(coro, timeout=timeout)
        
    except asyncio.TimeoutError:
        logger.critical(f"[{tool_name}] ⏳ CRASH DETECTED: Execution exceeded {timeout}s limit. Killing tool.")
        return default_return
        
    except Exception as e:
        logger.error(f"[{tool_name}] 💥 CRASH: {str(e)}", exc_info=True)
        import traceback
        logger.debug(traceback.format_exc())
        return default_return
