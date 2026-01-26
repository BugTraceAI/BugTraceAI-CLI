import asyncio
import shutil
from typing import List, Dict, Any
from loguru import logger
from bugtrace.core.config import settings

class PortScanner:
    def __init__(self):
        self.nmap_path = shutil.which("nmap")
        
    async def scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """
        Runs Nmap actively. 
        In SAFE_MODE, strictly limits arguments.
        """
        if not self.nmap_path:
            logger.warning("Nmap not found. Skipping port scan.")
            return {}
            
        logger.info(f"Scanning ports for {target}...")
        
        args = ["-p", ports, "-T4", "--open", "-oX", "-"]
        if settings.SAFE_MODE:
            # Safer scan
            args.extend(["-sT"]) # Connect scan (no raw packets)
        else:
            args.extend(["-sS", "-sV"]) # SYN Scan + Version Detection
            
        cmd = [self.nmap_path, target] + args
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            logger.error(f"Nmap failed: {stderr.decode()}")
            return {"error": stderr.decode()}
            
        return {"raw_xml": stdout.decode()}

port_scanner = PortScanner()
