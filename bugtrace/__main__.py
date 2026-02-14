# Apply aiohttp timeout patch FIRST - before any other imports
# This ensures all ClientSession instances have default timeouts
import bugtrace.utils.aiohttp_patch  # noqa: F401, E402

import asyncio
import sys
import typer
import warnings
from typing import Optional
from datetime import datetime
from rich.console import Console
from bugtrace.core.config import settings
from bugtrace.core.instance_lock import acquire_instance_lock
from pathlib import Path

# Suppress subprocess cleanup warnings (cosmetic issue only)
# These occur when subprocesses cleanup after event loop closes
# Functionality is not affected - just prevents confusing error messages
warnings.filterwarnings("ignore", category=RuntimeWarning,
                       module="asyncio.base_subprocess")
warnings.filterwarnings("ignore", message=".*Event loop is closed.*")

# Q-Learning WAF Strategy Router (for graceful shutdown persistence)
from bugtrace.tools.waf import strategy_router


def _save_qlearning_data():
    """Persist Q-Learning WAF bypass data on shutdown."""
    try:
        strategy_router.force_save()
    except Exception as e:
        # Silent fail on shutdown - Q-Learning data is non-critical
        # Don't log to avoid cluttering shutdown sequence
        pass


# Note: allow_interspersed_args must NOT be set at app level or it swallows subcommand options
app = typer.Typer(add_completion=False)
console = Console()

# Commands that don't need instance locking (read-only or special)
SKIP_LOCK_COMMANDS = {'agents', 'summary', 'mcp', 'tui'}


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context):
    """
    Check for existing BugTraceAI instances before running commands.
    """
    # Get the invoked command name
    command_name = ctx.invoked_subcommand

    # Skip instance check for read-only commands
    if command_name in SKIP_LOCK_COMMANDS:
        return

    # Skip if no command was invoked (just `bugtrace` with no args)
    if command_name is None:
        return

    # Check for updates (silent, cached — hits GitHub at most once per 24h)
    try:
        from bugtrace.utils.version_check import check_for_update_sync
        update = check_for_update_sync(settings.VERSION)
        if update and update.get("update_available"):
            console.print(
                f"[yellow]Update available: {settings.VERSION} → {update['latest_version']}[/yellow]  "
                f"[dim]Run: ./launcher.sh update[/dim]"
            )
    except Exception:
        pass

    # Build command string for lock file
    command_str = f"bugtrace {command_name}"
    if len(sys.argv) > 2:
        command_str = f"bugtrace {' '.join(sys.argv[1:])}"

    # Check for existing instance and acquire lock
    if not acquire_instance_lock(command_str):
        raise typer.Exit(code=1)

@app.command(name="scan")
def scan(
    target: str = typer.Argument(..., help="The target URL to scan (Hunter phase)"),
    url_list_file: Optional[str] = typer.Option(None, "--url-list-file", "-ul", help="File with URLs to scan (bypasses GoSpider, one URL per line)"),
    safe_mode: Optional[bool] = typer.Option(None, "--safe-mode", help="Override SAFE_MODE setting"),
    resume: bool = typer.Option(False, "--resume", help="Resume from previous state file"),
    clean: bool = typer.Option(False, "--clean", help="Clean previous scan data before starting"),
    xss: bool = typer.Option(False, "--xss", help="XSS-only mode"),
    sqli: bool = typer.Option(False, "--sqli", help="SQLi-only mode"),
    jwt: bool = typer.Option(False, "--jwt", help="JWT-only mode: Run only JWTAgent for focused testing"),
    lfi: bool = typer.Option(False, "--lfi", help="LFI-only mode: Run only LFI detection"),
    idor: bool = typer.Option(False, "--idor", help="IDOR-only mode: Run only IDORAgent"),
    ssrf: bool = typer.Option(False, "--ssrf", help="SSRF-only mode: Run only SSRFAgent"),
    param: Optional[str] = typer.Option(None, "--param", "-p", help="Parameter to test (for focused modes)")
):
    """Run the Discovery (Hunter) phase only."""
    _run_pipeline(target, phase="hunter", url_list_file=url_list_file, safe_mode=safe_mode, resume=resume, clean=clean, xss=xss, sqli=sqli, jwt=jwt, lfi=lfi, idor=idor, ssrf=ssrf, param=param)

@app.command(name="audit")
def audit(
    target: str = typer.Argument(..., help="The target URL to audit (Auditor phase)"),
    scan_id: Optional[int] = typer.Option(None, "--scan-id", help="Specific Scan ID to audit"),
):
    """Run the Audit (Auditor) phase only."""
    _run_pipeline(target, phase="manager", scan_id=scan_id)

@app.command(name="full")
def full_scan(
    target: str = typer.Argument(..., help="The target URL for full engagement"),
    url_list_file: Optional[str] = typer.Option(None, "--url-list-file", "-ul", help="File with URLs to scan (bypasses GoSpider, one URL per line)"),
    safe_mode: Optional[bool] = typer.Option(None, "--safe-mode", help="Override SAFE_MODE setting"),
    resume: bool = typer.Option(False, "--resume", help="Resume from previous state file"),
    clean: bool = typer.Option(False, "--clean", help="Clean previous scan data before starting"),
    continuous: bool = typer.Option(False, "--continuous", help="Run Auditor in parallel with Hunter"),
    xss: bool = typer.Option(False, "--xss", help="XSS-only mode"),
    sqli: bool = typer.Option(False, "--sqli", help="SQLi-only mode"),
    jwt: bool = typer.Option(False, "--jwt", help="JWT-only mode"),
    lfi: bool = typer.Option(False, "--lfi", help="LFI-only mode"),
    idor: bool = typer.Option(False, "--idor", help="IDOR-only mode"),
    ssrf: bool = typer.Option(False, "--ssrf", help="SSRF-only mode"),
    param: Optional[str] = typer.Option(None, "--param", "-p", help="Parameter to test (for focused modes)")
):
    """Run Hunter followed by Auditor (The complete professional workflow)."""
    _run_pipeline(target, phase="all", url_list_file=url_list_file, safe_mode=safe_mode, resume=resume, clean=clean, continuous=continuous, xss=xss, sqli=sqli, jwt=jwt, lfi=lfi, idor=idor, ssrf=ssrf, param=param)

@app.command(name="serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload on code changes")
):
    """Start the FastAPI server for REST API access."""
    from bugtrace.api.server import start_api_server

    console.print(f"\n[bold green]Starting BugTraceAI API Server[/bold green]")
    console.print(f"[bold green]Host:[/bold green] {host}")
    console.print(f"[bold green]Port:[/bold green] {port}")
    console.print(f"[bold green]Docs:[/bold green] http://{host}:{port}/docs")
    console.print(f"[bold green]Health:[/bold green] http://{host}:{port}/health")
    console.print("")

    try:
        start_api_server(host=host, port=port, reload=reload)
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Server error:[/bold red] {e}")
        import traceback
        traceback.print_exc()

@app.command(name="mcp")
def mcp():
    """Start the MCP server for AI assistant integration (STDIO transport)."""
    from bugtrace.mcp.server import run_mcp_server
    run_mcp_server()

@app.command(name="summary")
def summary(
    target: Optional[str] = typer.Argument(None, help="Target URL (uses latest scan for this target)"),
    scan_id: Optional[int] = typer.Option(None, "--scan-id", "-s", help="Specific scan ID"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
):
    """Show aggregated findings summary by severity for a scan."""
    from bugtrace.core.summary import generate_scan_summary, format_summary_table, format_summary_json

    try:
        scan_summary = generate_scan_summary(scan_id=scan_id, target_url=target)

        if json_output:
            console.print(format_summary_json(scan_summary))
        else:
            console.print(format_summary_table(scan_summary))
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command(name="agents")
def agents():
    """List all available security testing agents."""
    from rich.table import Table

    table = Table(title="BugTraceAI Security Agents", show_header=True)
    table.add_column("Agent", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("CWE", style="yellow")
    table.add_column("Description")

    # Core agents
    table.add_row("XSSAgent", "Cross-Site Scripting", "CWE-79", "Detects reflected, stored, and DOM-based XSS")
    table.add_row("SQLMapAgent", "SQL Injection", "CWE-89", "Detects SQL injection via SQLMap integration")
    table.add_row("JWTAgent", "JWT Vulnerabilities", "CWE-347", "Analyzes JWT tokens for weaknesses")
    table.add_row("LFIAgent", "Local File Inclusion", "CWE-98", "Detects path traversal and LFI")
    table.add_row("SSRFAgent", "Server-Side Request Forgery", "CWE-918", "Detects SSRF via URL parameters")
    table.add_row("IDORAgent", "Insecure Direct Object Reference", "CWE-639", "Detects authorization bypass")
    table.add_row("XXEAgent", "XML External Entity", "CWE-611", "Detects XXE in XML parsers")
    table.add_row("RCEAgent", "Remote Code Execution", "CWE-94", "Detects command injection")

    # New v2.2 agents
    table.add_row("OpenRedirectAgent", "Open Redirect", "CWE-601", "Detects URL redirection vulnerabilities")
    table.add_row("PrototypePollutionAgent", "Prototype Pollution", "CWE-1321", "Detects JS prototype pollution with RCE escalation")

    # Support agents
    table.add_row("CSTIAgent", "Client-Side Template Injection", "CWE-94", "Detects template injection")
    table.add_row("APISecurityAgent", "API Security", "Multiple", "API endpoint security analysis")
    table.add_row("ChainDiscoveryAgent", "Vulnerability Chaining", "Multiple", "Discovers attack chains")

    console.print(table)
    console.print("\n[dim]Run with: bugtrace scan <url> or bugtrace full <url>[/dim]")


@app.command(name="tui")
def tui(
    target: Optional[str] = typer.Argument(
        None, help="Target URL to scan (optional, can be entered in TUI)"
    ),
    demo: bool = typer.Option(
        False, "--demo", help="Run in demo mode with animated mock data"
    ),
):
    """Launch the Textual-based Terminal User Interface.

    This provides an interactive dashboard with:
    - Real-time scan progress visualization
    - Agent swarm monitoring
    - Findings browser
    - System metrics

    If a target URL is provided, the scan will start automatically.

    Examples:
        bugtrace tui                     # Open TUI without starting scan
        bugtrace tui https://example.com # Open TUI and start scanning
        bugtrace tui --demo              # Open TUI with animated demo data
    """
    try:
        from bugtrace.core.ui.tui import BugTraceApp

        app_instance = BugTraceApp(target=target, demo_mode=demo)
        app_instance.run()
    except KeyboardInterrupt:
        # Clean exit on CTRL+C
        pass
    except ImportError as e:
        console.print(f"[bold red]Error:[/bold red] Textual TUI dependencies not installed.")
        console.print(f"[dim]Install with: pip install textual[/dim]")
        console.print(f"[dim]Details: {e}[/dim]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]TUI Error:[/bold red] {e}")
        import traceback
        traceback.print_exc()
        raise typer.Exit(code=1)


def _load_url_list(file_path: str, target: str) -> list:
    """
    Load URLs from file, one per line.
    Filters URLs to only include those from the target domain.
    Ignores empty lines and comments (#).

    Args:
        file_path: Path to file containing URLs
        target: Base target URL for domain filtering

    Returns:
        List of URLs from the same domain as target
    """
    from pathlib import Path
    from urllib.parse import urlparse

    if not Path(file_path).exists():
        raise FileNotFoundError(f"URL list file not found: {file_path}")

    # Extract base domain from target
    target_parsed = urlparse(target)
    target_domain = target_parsed.netloc

    urls = []
    filtered_count = 0

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Validate URL format
            try:
                parsed = urlparse(line)
                if not parsed.scheme or not parsed.netloc:
                    console.print(f"[yellow]Warning: Line {line_num} - Invalid URL format: {line}[/yellow]")
                    continue

                # Filter by domain
                if parsed.netloc == target_domain:
                    urls.append(line)
                else:
                    filtered_count += 1
                    console.print(f"[dim]Skipping URL from different domain: {line}[/dim]")

            except Exception as e:
                console.print(f"[yellow]Warning: Line {line_num} - Could not parse URL: {line} ({e})[/yellow]")
                continue

    if not urls:
        raise ValueError(f"No valid URLs found in {file_path} matching domain {target_domain}")

    console.print(f"[green]✅ Loaded {len(urls)} URLs from {file_path}[/green]")
    if filtered_count > 0:
        console.print(f"[yellow]⚠️  Filtered {filtered_count} URLs from different domains[/yellow]")

    return urls

def _run_pipeline(target, phase="all", url_list_file=None, safe_mode=None, resume=False, clean=False, xss=False, sqli=False, jwt=False, lfi=False, idor=False, ssrf=False, param=None, scan_id=None, continuous=False):
    """Internal helper to run the pipeline phases."""
    if safe_mode is not None:
        settings.SAFE_MODE = safe_mode

    # Load URL list if provided
    url_list = None
    if url_list_file:
        try:
            url_list = _load_url_list(url_list_file, target)
        except Exception as e:
            console.print(f"[bold red]Error loading URL list:[/bold red] {e}")
            raise typer.Exit(code=1)

    # Check for focused mode
    if xss or sqli or lfi or jwt or idor or ssrf:
        _run_focused_mode(target, xss=xss, sqli=sqli, lfi=lfi, jwt=jwt, idor=idor, ssrf=ssrf, param=param)
        return

    # Boot sequence
    if not _run_boot_sequence():
        return

    # Display framework info
    _display_framework_info(target)

    # Execute phases
    try:
        asyncio.run(_execute_phases(target, phase, resume, clean, scan_id, continuous, url_list))
    except KeyboardInterrupt:
        console.print("\n[yellow]Engagement aborted by user.[/yellow]")
    except Exception as e:
        import traceback
        traceback.print_exc()
        console.print(f"\n[bold red]Fatal Framework Error:[/bold red] {e}")
    finally:
        _save_qlearning_data()


def _run_boot_sequence() -> bool:
    """Run boot sequence and return success status."""
    from bugtrace.core.boot import BootSequence

    boot_success = False
    try:
        boot_loader = BootSequence()
        boot_success = asyncio.run(boot_loader.run_checks())
    except KeyboardInterrupt:
        console.print("\n[yellow]Deployment cancelled by user.[/yellow]")
        raise typer.Exit()
    except Exception as e:
        console.print(f"\n[bold red]Boot Crash:[/bold red] {e}")
        boot_success = False

    if not boot_success:
        if not typer.confirm("Safety checks failed. Deploy framework anyway?", default=False):
            console.print("[red]Shutdown initiated.[/red]")
            raise typer.Exit(code=1)

    return True


def _display_framework_info(target: str):
    """Display framework deployment information."""
    console.print(f"\n[bold green]Deploying Framework against:[/bold green] [cyan]{target}[/cyan]")
    console.print(f"[bold green]Security Level:[/bold green] [{'green' if settings.SAFE_MODE else 'red'}]{'SAFE' if settings.SAFE_MODE else 'ASSAULT'}[/]")
    console.print(f"[bold green]Framework Capacity:[/bold green] Depth={settings.MAX_DEPTH}, Concurrency={settings.MAX_CONCURRENT_URL_AGENTS}")
    console.print(f"[bold cyan]Architecture:[/bold cyan] Sequential Pipeline (V2 Architecture)")


async def _execute_phases(target: str, phase: str, resume: bool, clean: bool, scan_id: int, continuous: bool, url_list: Optional[list] = None):
    """Execute scan phases with dashboard UI."""
    from bugtrace.core.database import get_db_manager
    from bugtrace.core.ui import dashboard
    from rich.live import Live
    from urllib.parse import urlparse

    db = get_db_manager()

    # Setup output directory
    common_output_dir = _setup_output_directory(target)

    # Clean environment if requested
    if clean and phase != "manager":
        from bugtrace.utils.janitor import clean_environment
        clean_environment()
        console.print("[yellow]🧹 Previous scan data cleaned.[/yellow]")

    # Initialize dashboard
    dashboard.reset()
    dashboard.start_keyboard_listener()

    # Start stop monitor thread
    stop_thread = _start_stop_monitor_thread(dashboard)

    try:
        with Live(dashboard, refresh_per_second=4, screen=True):
            dashboard.active = True
            dashboard.set_status("Running", "Initializing pipeline...")

            # Execute Hunter phase
            orchestrator = None
            if phase in ["hunter", "all"]:
                orchestrator = await _run_hunter_phase(target, db, resume, common_output_dir, url_list)

            # Execute Auditor phase
            if phase in ["manager", "all"]:
                await _run_auditor_phase(target, db, scan_id, orchestrator, common_output_dir, continuous)

            dashboard.active = False
    finally:
        # ALWAYS ensure keyboard listener restores terminal settings
        dashboard.active = False
        dashboard.stop_keyboard_listener()


def _setup_output_directory(target: str) -> Path:
    """Setup consistent output directory for scan."""
    from urllib.parse import urlparse

    domain = urlparse(target).netloc or "unknown"
    if ":" in domain:
        domain = domain.split(":")[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    common_output_dir = Path(settings.REPORT_DIR) / f"{domain}_{timestamp}"
    return common_output_dir


def _start_stop_monitor_thread(dashboard):
    """Start daemon thread to monitor stop requests."""
    import threading

    def _stop_monitor_thread():
        import time as _time
        while dashboard.active:
            _time.sleep(0.5)
            if not dashboard.stop_requested:
                continue

            _time.sleep(3)  # Grace period
            if not dashboard.active:
                continue

            _perform_emergency_shutdown()

    stop_thread = threading.Thread(target=_stop_monitor_thread, daemon=True)
    stop_thread.start()
    return stop_thread


def _perform_emergency_shutdown():
    """Perform emergency shutdown via SIGKILL."""
    import os, signal as sig_mod
    try:
        os.killpg(os.getpgrp(), sig_mod.SIGKILL)
    except Exception:
        os._exit(1)


async def _run_hunter_phase(target: str, db, resume: bool, common_output_dir: Path, url_list: Optional[list] = None):
    """Run Hunter (Discovery) phase."""
    # Check for active scan and auto-resume
    resume = await _check_and_resume_scan(target, db, resume)

    # Create and run orchestrator
    from bugtrace.core.team import TeamOrchestrator
    orchestrator = TeamOrchestrator(
        target,
        resume=resume,
        max_depth=settings.MAX_DEPTH,
        max_urls=settings.MAX_URLS,
        use_vertical_agents=True,
        output_dir=common_output_dir,
        url_list=url_list
    )

    # Display mode info
    if url_list:
        console.print(f"\n[bold green]🏹 Launching Hunter Phase (Scan ID: {orchestrator.scan_id}) - URL List Mode ({len(url_list)} URLs)[/bold green]")
    else:
        console.print(f"\n[bold green]🏹 Launching Hunter Phase (Scan ID: {orchestrator.scan_id})[/bold green]")

    await orchestrator.start()

    # Phase transition cleanup
    from bugtrace.tools.visual.browser import browser_manager
    await browser_manager.stop()

    return orchestrator


async def _check_and_resume_scan(target: str, db, resume: bool) -> bool:
    """Check for active scan state from files (DB = write-only)."""
    try:
        from bugtrace.core.state_manager import StateManager
        sm = StateManager(target)
        state = sm.load_state()
        if state and not resume:
            processed = len(state.get("processed_urls", []))
            queued = len(state.get("url_queue", []))
            total = processed + queued
            if total > 0 and queued > 0:
                pct = int((processed / total * 100))
                console.print(f"\n[bold yellow]⚠️  Found UNFINISHED SCAN for {target}[/bold yellow]")
                console.print(f"   • Progress: {processed} analyzed / {total} total (~{pct}%)")
                console.print(f"   • Queued: {queued} URLs waiting")
                console.print("[green]🔄 Auto-resuming detected active scan...[/green]")
                resume = True
    except Exception as e:
        console.print(f"[dim]State check warning: {e}[/dim]")

    return resume


async def _run_auditor_phase(target: str, db, scan_id: int, orchestrator, common_output_dir: Path, continuous: bool):
    """Run Auditor (Validator) phase."""
    from bugtrace.core.validator_engine import ValidationEngine

    sid = scan_id or (orchestrator.scan_id if orchestrator else None)

    # Fallback: use 0 (DB writes will still work, just won't match a specific scan)
    if not sid:
        sid = 0

    out_dir = common_output_dir if common_output_dir else None

    if not sid:
        console.print("[red]Error: Could not determine Scan ID for auditing.[/red]")
        return

    console.print(f"\n[bold yellow]🛡️  Launching Auditor (Validator) Phase (Processing findings for Scan {sid})...[/bold yellow]")
    engine = ValidationEngine(scan_id=sid, output_dir=out_dir, scan_dir=out_dir, target_url=target)
    await engine.run(continuous=continuous)
    console.print(f"[bold green]✅ Auditor Phase Complete.[/bold green]")


def _run_focused_mode(target: str, xss: bool = False, sqli: bool = False, lfi: bool = False, jwt: bool = False, idor: bool = False, ssrf: bool = False, param: str = None):
    """
    Run focused testing mode - bypasses DAST and runs only specified agent.
    Useful for debugging and targeted testing.
    """
    # Setup and display
    params, report_dir = _setup_focused_mode(target, param, xss, sqli, jwt, lfi, idor, ssrf)

    # Run agent with dashboard
    try:
        result = _run_focused_agent_with_dashboard(target, params, report_dir, xss, sqli, jwt, lfi, idor, ssrf)
        _display_focused_results(target, result, params, report_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Test aborted by user.[/yellow]")
    except Exception as e:
        import traceback
        traceback.print_exc()
        console.print(f"\n[bold red]Error:[/bold red] {e}")
    finally:
        _save_qlearning_data()


def _setup_focused_mode(target: str, param: str, xss: bool, sqli: bool, jwt: bool, lfi: bool, idor: bool, ssrf: bool):
    """Setup focused mode - parse params and create output directory."""
    from urllib.parse import urlparse, parse_qs
    from datetime import datetime

    console.print(f"\n[bold magenta]🎯 FOCUSED TESTING MODE[/bold magenta]")
    console.print(f"[bold green]Target:[/bold green] [cyan]{target}[/cyan]")

    # Determine parameters
    params = _parse_focused_params(target, param)

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_name = "xss" if xss else ("sqli" if sqli else ("jwt" if jwt else ("lfi" if lfi else ("idor" if idor else "ssrf"))))
    report_dir = Path(settings.REPORT_DIR) / f"focused_{mode_name}_{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold green]Output:[/bold green] {report_dir}")
    console.print("")

    return params, report_dir


def _parse_focused_params(target: str, param: str):
    """Parse parameters for focused mode testing."""
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(target)
    if param:
        params = [p.strip() for p in param.split(',')]
        console.print(f"[bold green]Parameters:[/bold green] {', '.join(params)}")
    else:
        query_params = parse_qs(parsed.query)
        params = list(query_params.keys()) if query_params else []
        if params:
            console.print(f"[bold green]URL Parameters:[/bold green] {', '.join(params)}")
        else:
            console.print(f"[bold green]Parameters:[/bold green] [cyan]Auto-discovery mode[/cyan]")

    return params


def _run_focused_agent_with_dashboard(target: str, params, report_dir: Path, xss: bool, sqli: bool, jwt: bool, lfi: bool, idor: bool, ssrf: bool):
    """Run the focused agent with dashboard UI."""
    from bugtrace.core.ui import dashboard
    from rich.live import Live

    dashboard.reset()
    dashboard.start_keyboard_listener()

    result = None
    try:
        with Live(dashboard, refresh_per_second=4, screen=True):
            dashboard.active = True
            dashboard.set_status("Running", "Initializing focused agent...")
            result = asyncio.run(_execute_focused_agent(target, params, report_dir, xss, sqli, jwt, lfi, idor, ssrf))
            dashboard.active = False

            if dashboard.stop_requested:
                _handle_emergency_stop()
    finally:
        # ALWAYS ensure keyboard listener restores terminal settings
        dashboard.active = False
        dashboard.stop_keyboard_listener()

    return result


def _execute_focused_agent(target: str, params, report_dir: Path, xss: bool, sqli: bool, jwt: bool, lfi: bool, idor: bool, ssrf: bool):
    """Execute the appropriate focused agent."""
    from bugtrace.core.ui import dashboard

    async def run_agent():
        dashboard.current_phase = "FOCUSED_TEST"
        return await _select_and_run_agent(target, params, report_dir, xss, sqli, jwt, lfi, idor, ssrf)

    return run_agent()


async def _select_and_run_agent(target: str, params, report_dir: Path, xss: bool, sqli: bool, jwt: bool, lfi: bool, idor: bool, ssrf: bool):
    """Select and run the appropriate agent based on flags."""
    if xss:
        return await _run_xss_agent(target, params, report_dir)
    if jwt:
        return await _run_jwt_agent(target, params)
    if sqli:
        return await _run_sqli_agent(target, params, report_dir)
    if lfi:
        return await _run_lfi_agent(target, params, report_dir)
    if idor:
        return await _run_idor_agent(target, params, report_dir)
    if ssrf:
        return await _run_ssrf_agent(target, params, report_dir)
    return None


async def _run_xss_agent(target: str, params, report_dir: Path):
    """Run XSS agent."""
    if params:
        console.print(f"[bold yellow]🔥 Running XSSAgent on param: {', '.join(params)}[/bold yellow]\n")
    else:
        console.print("[bold yellow]🔥 Running XSSAgent (autonomous mode)...[/bold yellow]\n")

    from bugtrace.agents.xss import XSSAgent  # Use package, not monolith
    agent = XSSAgent(target, params if params else None, report_dir)
    return await agent.run_loop()


async def _run_jwt_agent(target: str, params):
    """Run JWT agent."""
    console.print("[bold yellow]🔑 Running JWTAgent...[/bold yellow]\n")

    token = params[0] if params else None
    if not token:
        console.print("[bold red]ERROR: For JWT focused mode, you must provide the token via --param 'eyJ...'[/bold red]")
        return {"findings": [], "error": "Token required in --param"}

    from bugtrace.agents.jwt_agent import run_jwt_analysis
    return await run_jwt_analysis(token, target)


async def _run_sqli_agent(target: str, params, report_dir: Path):
    """Run SQLi agent."""
    console.print("[bold yellow]💉 Running SQLMapAgent...[/bold yellow]\n")
    from bugtrace.agents.sqlmap_agent import SQLMapAgent
    agent = SQLMapAgent(target, params, report_dir)
    return await agent.run_loop()


async def _run_lfi_agent(target: str, params, report_dir: Path):
    """Run LFI agent."""
    console.print("[bold yellow]📁 Running LFIAgent...[/bold yellow]\n")
    from bugtrace.agents.lfi_agent import LFIAgent
    agent = LFIAgent(target, params if params else None, report_dir)
    return await agent.run_loop()


async def _run_idor_agent(target: str, params, report_dir: Path):
    """Run IDOR agent."""
    console.print("[bold yellow]👤 Running IDORAgent...[/bold yellow]\n")
    from bugtrace.agents.idor_agent import IDORAgent

    idor_params = []
    if params:
        for p in params:
            idor_params.append({"parameter": p, "original_value": "1"})

    agent = IDORAgent(target, idor_params if idor_params else None, report_dir)
    return await agent.run_loop()


async def _run_ssrf_agent(target: str, params, report_dir: Path):
    """Run SSRF agent."""
    console.print("[bold yellow]🌐 Running SSRFAgent...[/bold yellow]\n")
    from bugtrace.agents.ssrf_agent import SSRFAgent
    agent = SSRFAgent(target, params if params else None, report_dir)
    return await agent.run_loop()


def _handle_emergency_stop():
    """Handle emergency stop request."""
    console.print("\n[bold red]🛑 Emergency stop requested. Cleaning up and exiting...[/bold red]")
    import os
    import signal
    try:
        os.killpg(os.getpgrp(), signal.SIGKILL)
    except Exception:
        import sys
        sys.exit(1)


def _display_focused_results(target: str, result: dict, params, report_dir: Path):
    """Display results from focused mode testing."""
    findings = result.get("findings", [])
    validated = [f for f in findings if f.get("validated")]
    potential = [f for f in findings if not f.get("validated")]

    console.print(f"\n[bold cyan]{'='*50}[/bold cyan]")
    console.print(f"[bold green]✅ RESULTS[/bold green]")
    console.print(f"[bold cyan]{'='*50}[/bold cyan]")
    console.print(f"  Total findings: {len(findings)}")
    console.print(f"  [green]Validated:[/green] {len(validated)}")
    console.print(f"  [yellow]Potential:[/yellow] {len(potential)}")

    if validated:
        console.print(f"\n[bold green]Validated Findings:[/bold green]")
        for f in validated:
            console.print(f"  • {f.get('type')}: {f.get('parameter')} - {f.get('payload', '')[:50]}...")

        # Generate report
        from bugtrace.agents.reporting import ReportingAgent
        reporting = ReportingAgent(target)
        console.print(f"\n[bold yellow]📄 Generating professional report...[/bold yellow]")
        asyncio.run(reporting.generate_final_report(
            findings,
            [target],
            {"mode": "focused_test", "params": params},
            report_dir
        ))

    console.print(f"\n[bold]Report saved to:[/bold] {report_dir}")


if __name__ == "__main__":
    app()

