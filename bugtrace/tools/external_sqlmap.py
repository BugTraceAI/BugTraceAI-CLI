"""ExternalTools mixin."""

from __future__ import annotations

import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin

from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import extract_sqlmap_verdict
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    ToolError, DockerError, DockerTimeoutError, DockerNotFoundError,
    SubprocessError, FuzzerError, FuzzerTimeoutError, NucleiError, JSONParseError,
)
import bugtrace.tools.external_util as _eu
from bugtrace.tools.external_util import *  # noqa: F401,F403

logger = get_logger("tools.external")


class ExternalSqlmapMixin:
    """SQLMap docker runner helpers."""

    def _build_sqlmap_command(
        self,
        url: str,
        target_param: Optional[str],
        cookies: Optional[List[Dict]],
        technique: Optional[str] = None,
        exploit_mode: bool = False
    ) -> tuple[List[str], str]:
        """Build SQLMap command and reproduction command.

        Args:
            technique: SQLMap technique hint from internal checks.
                       E=Error, B=Boolean, U=Union, S=Stacked, T=Time, Q=Inline
                       If None, uses all techniques (BEUSTQ).
        """
        tech = technique if technique else "BEUSTQ"
        reproduction_cmd = f"sqlmap -u '{url}' --batch --random-agent --technique={tech} --level 2 --risk 2"

        cmd = [
            "-u", url,
            "--batch",
            "--random-agent",
            f"--technique={tech}",
            "--level", "2",
            "--risk", "2",
            "--parse-errors",
            "--flush-session",
            "--output-dir=/tmp"
        ]

        if target_param:
            cmd.extend(["-p", target_param])
            reproduction_cmd += f" -p {target_param}"
            cmd.append("--skip-urlencoding")
        else:
            cmd.append("--forms")
            reproduction_cmd += " --forms"

        if exploit_mode:
            # Aggressive extraction for confirmed flaws
            cmd.extend(["--dbs", "--users", "--passwords"])
            reproduction_cmd += " --dbs --users --passwords"

        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.append(f"--cookie={cookie_str}")
            reproduction_cmd += f" --cookie='{cookie_str}'"

        return cmd, reproduction_cmd

    def _parse_sqlmap_output(self, output: str) -> Optional[tuple[str, str]]:
        """Parse SQLMap output for vulnerability detection."""
        param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
        type_match = re.search(r"Type:\s+(.+?)\s", output)

        if param_match and type_match:
            return param_match.group(1), type_match.group(1)
        return None

    async def run_sqlmap(
        self,
        url: str,
        cookies: List[Dict] = None,
        target_param: str = None,
        technique: str = None,
        exploit_mode: bool = False
    ) -> Optional[Dict]:
        """
        Runs SQLMap active scan (native preferred, Docker fallback).
        Targets specific parameters found by GoSpider.

        Args:
            technique: Technique hint from internal checks (E/B/U/S/T/Q or combination).
                       If provided, SQLMap will try this technique first for faster detection.
        """
        native = self._native_tools.get("sqlmap")
        if not native and not self.docker_cmd:
            return None

        self._record_tool_run("sqlmap")
        mode = "native" if native else "Docker"
        target_info = f"param '{target_param}' on {url}" if target_param else url
        tech_info = f" (technique: {technique})" if technique else ""
        logger.info(f"Starting SQLMap ({mode}) on {target_info}{tech_info}...")
        dashboard.log(f"[External] Launching SQLMap ({mode}) against {target_info}{tech_info}", "INFO")

        cmd, reproduction_cmd = self._build_sqlmap_command(url, target_param, cookies, technique, exploit_mode=exploit_mode)

        if native:
            output = await self._run_native("sqlmap", [native] + cmd, tolerate_nonzero=True)
        else:
            output = await self._run_container("googlesky/sqlmap:latest", cmd)

        result = self._parse_sqlmap_output(output)
        if result:
            param, vuln_type = result
            return {
                "vulnerable": True,
                "parameter": param,
                "type": vuln_type,
                "reproduction_command": reproduction_cmd,
                "output_snippet": extract_sqlmap_verdict(output)
            }
        return None

