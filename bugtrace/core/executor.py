import asyncio
import signal
import subprocess
from asyncio.subprocess import Process
from typing import Optional, Tuple, List, Dict
from loguru import logger
from bugtrace.utils.janitor import clean_environment # We reuse our Janitor logic

class ToolExecutor:
    """
    The Enforcer.
    Executes external tools with iron-fist control over lifecycle, timeouts, and resources.
    Specialized execution engine for local processes.
    """

    @staticmethod
    async def run(
        command: List[str], 
        timeout: float = 60.0, 
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        tool_name: str = "Unknown"
    ) -> Tuple[str, str, int]:
        """
        Runs a command asynchronously with a strict timeout.
        
        Returns:
            (stdout, stderr, return_code)
        """
        process: Optional[Process] = None
        
        try:
            logger.debug(f"[{tool_name}] Executing: {' '.join(command)}")
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                # Create a new session group to kill the whole tree if needed
                start_new_session=True 
            )

            # Wait with timeout
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            
            return stdout, stderr, process.returncode

        except asyncio.TimeoutError:
            logger.critical(f"[{tool_name}] ⏳ TIMEOUT ({timeout}s). Killing process tree...")
            
            if process:
                try:
                    # Kill the entire process group (Process + Children)
                    import os
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    logger.info(f"[{tool_name}] 💀 Process group killed.")
                except Exception as kill_err:
                    logger.error(f"[{tool_name}] Failed to kill process: {kill_err}")
            
            return "", "TIMEOUT_EXCEEDED", -1

        except Exception as e:
            logger.error(f"[{tool_name}] 💥 Execution Error: {e}")
            return "", str(e), -1
        
        finally:
            # Final safety net
            if process and process.returncode is None:
                try:
                    process.kill()
                except: 
                    pass
