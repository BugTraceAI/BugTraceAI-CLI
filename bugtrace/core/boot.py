import asyncio
import os
import sys
from typing import List, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich import box
from dotenv import load_dotenv

# Load env immediately
load_dotenv()

from bugtrace.core.config import settings
# Lazy import for llm_client to avoid circular or early init issues if possible, 
# but verifying connectivity requires it.
from bugtrace.core.llm_client import llm_client

console = Console()

class BootSequence:
    """
    Orchestrates the system startup checks with a visual UI.
    Verifies: Environment, Internet, AI Models, Browser.
    """
    def __init__(self):
        self.checks = [
            ("Environment Variables", self._check_env),
            ("Network Connectivity", self._check_network),
            ("AI Intelligence Grid", self._check_ai),
            ("Visual Engine (Browser)", self._check_browser),
        ]
        self.results: List[Tuple[str, str, str]] = [] # (Name, Status, Details)
        self.has_critical_error = False

    async def run_checks(self) -> bool:
        """
        Runs all checks and displays the loading screen.
        Returns True if startup should proceed, False if aborted.
        """
        self._display_boot_banner()

        await self._execute_boot_sequence()

        self._print_summary()

        return self._evaluate_boot_result()

    def _display_boot_banner(self) -> None:
        """Display the initial boot banner."""
        console.clear()
        console.print(Panel.fit(
            f"[bold cyan]BugtraceAI-CLI[/bold cyan] [dim]v{settings.VERSION} Phoenix Edition[/dim]\n"
            "[italic]Initializing Cyber-Reconnaissance Framework...[/italic]",
            box=box.ROUNDED,
            border_style="cyan"
        ))

    async def _execute_boot_sequence(self) -> None:
        """Execute all boot checks with progress tracking."""
        with Progress(
            SpinnerColumn("dots", style="bold cyan"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=None, style="cyan", complete_style="bold cyan"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            expand=True
        ) as progress:

            boot_task = progress.add_task("System Boot...", total=len(self.checks))

            for name, check_func in self.checks:
                await self._run_single_check(progress, boot_task, name, check_func)

    async def _run_single_check(
        self,
        progress: Progress,
        boot_task,
        name: str,
        check_func
    ) -> None:
        """Run a single boot check and record result."""
        progress.update(boot_task, description=f"Verifying: {name}...")

        try:
            status, details = await check_func()
            self._record_check_result(name, status, details)
        except Exception as e:
            self.has_critical_error = True
            self.results.append((name, "[bold red]ERROR[/]", str(e)))

        progress.advance(boot_task)
        await asyncio.sleep(0.3)  # Visual pacing

    def _record_check_result(self, name: str, status: str, details: str) -> None:
        """Record the result of a boot check."""
        if status != "OK":
            if "CRITICAL" in details:
                self.has_critical_error = True
                self.results.append((name, "[bold red]FAIL[/]", details))
            else:
                self.results.append((name, "[bold yellow]WARN[/]", details))
        else:
            self.results.append((name, "[bold green]OK[/]", details))

    def _evaluate_boot_result(self) -> bool:
        """Evaluate boot results and return success status."""
        if self.has_critical_error:
            console.print("\n[bold red]System Boot Failed. Critical errors detected.[/bold red]")
            return False

        return True

    def _print_summary(self):
        """Prints a neat table of the check results."""
        table = Table(show_header=True, header_style="bold white", box=box.SIMPLE, expand=True)
        table.add_column("Component", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Details")
        
        for name, status, details in self.results:
            table.add_row(name, status, details)
            
        console.print(table)

    async def _check_env(self) -> Tuple[str, str]:
        """Checks specific critical env vars."""
        if not settings.OPENROUTER_API_KEY:
            return "WARN", "OPENROUTER_API_KEY missing. AI features disabled."
        return "OK", "Configuration loaded."

    async def _check_network(self) -> Tuple[str, str]:
        """Simple ping to external world."""
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://openrouter.ai", timeout=3) as resp:
                    return self._evaluate_network_response(resp.status)
        except Exception as e:
            return "FAIL", f"CRITICAL: No Internet ({str(e)})"

    def _evaluate_network_response(self, status: int) -> Tuple[str, str]:
        """Evaluate network check response status."""
        if status < 500:
            return "OK", "Internet reachable."
        return "WARN", f"OpenRouter status {status}."

    async def _check_ai(self) -> Tuple[str, str]:
        """Uses llm_client to verify connectivity."""
        if not settings.OPENROUTER_API_KEY:
            return "WARN", "Skipped (No Key)"
            
        try:
            # We assume verify_connectivity returns True/False
            # We can reuse the logic we added or make a simplified call here.
            # Using the verify_connectivity method we added to LLMClient earlier.
            is_online = await llm_client.verify_connectivity()
            if is_online:
                 # Check which model responded (optional, but verify_connectivity logs it)
                 return "OK", "Brain Online."
            else:
                 return "FAIL", "CRITICAL: All AI Models unresponsive."
        except Exception as e:
            return "FAIL", f"CRITICAL: AI Client crashed: {e}"

    async def _check_browser(self) -> Tuple[str, str]:
        """Checks if playwright browsers are installed."""
        # Simple check: try to find the executable path or just assume OK if installed.
        # A full browser launch might be too slow for boot, but we can try a dry run logic.
        from playwright.async_api import async_playwright
        try:
            async with async_playwright() as p:
                # Just checks if we can launch the context manager, verifying binaries exist
                await p.chromium.launch(headless=True)
                return "OK", "Chromium Engine Ready."
        except Exception as e:
            return "FAIL", f"CRITICAL: Browser Engine failed. Run 'playwright install'. ({e})"
