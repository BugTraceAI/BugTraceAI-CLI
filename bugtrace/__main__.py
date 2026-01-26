import asyncio
import typer
import click
import warnings
from typing import Optional
from datetime import datetime
from rich.console import Console
from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.config import settings
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
    except Exception:
        pass  # Silent fail - don't interrupt shutdown


# Configure Click context to allow options after positional args: ./bugtraceai-cli URL --xss
CONTEXT_SETTINGS = dict(allow_interspersed_args=True)
app = typer.Typer(context_settings=CONTEXT_SETTINGS, add_completion=False)
console = Console()

@app.command(name="scan")
def scan(
    target: str = typer.Argument(..., help="The target URL to scan (Hunter phase)"),
    safe_mode: Optional[bool] = typer.Option(None, "--safe-mode", help="Override SAFE_MODE setting"),
    resume: bool = typer.Option(False, "--resume", help="Resume from previous state file"),
    xss: bool = typer.Option(False, "--xss", help="XSS-only mode"),
    sqli: bool = typer.Option(False, "--sqli", help="SQLi-only mode"),
    jwt: bool = typer.Option(False, "--jwt", help="JWT-only mode: Run only JWTAgent for focused testing"),
    lfi: bool = typer.Option(False, "--lfi", help="LFI-only mode: Run only LFI detection"),
    idor: bool = typer.Option(False, "--idor", help="IDOR-only mode: Run only IDORAgent"),
    ssrf: bool = typer.Option(False, "--ssrf", help="SSRF-only mode: Run only SSRFAgent"),
    param: Optional[str] = typer.Option(None, "--param", "-p", help="Parameter to test (for focused modes)")
):
    """Run the Discovery (Hunter) phase only."""
    _run_pipeline(target, phase="hunter", safe_mode=safe_mode, resume=resume, xss=xss, sqli=sqli, jwt=jwt, lfi=lfi, idor=idor, ssrf=ssrf, param=param)

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
    safe_mode: Optional[bool] = typer.Option(None, "--safe-mode", help="Override SAFE_MODE setting"),
    resume: bool = typer.Option(False, "--resume", help="Resume from previous state file"),
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
    _run_pipeline(target, phase="all", safe_mode=safe_mode, resume=resume, continuous=continuous, xss=xss, sqli=sqli, jwt=jwt, lfi=lfi, idor=idor, ssrf=ssrf, param=param)

def _run_pipeline(target, phase="all", safe_mode=None, resume=False, xss=False, sqli=False, jwt=False, lfi=False, idor=False, ssrf=False, param=None, scan_id=None, continuous=False):
    """Internal helper to run the pipeline phases."""
    if safe_mode is not None:
        settings.SAFE_MODE = safe_mode

    # --- FOCUSED TESTING MODE ---
    if xss or sqli or lfi or jwt or idor or ssrf:
        _run_focused_mode(target, xss=xss, sqli=sqli, lfi=lfi, jwt=jwt, idor=idor, ssrf=ssrf, param=param)
        return

    # --- BOOT SEQUENCE ---
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

    console.print(f"\n[bold green]Deploying Framework against:[/bold green] [cyan]{target}[/cyan]")
    console.print(f"[bold green]Security Level:[/bold green] [{'green' if settings.SAFE_MODE else 'red'}]{'SAFE' if settings.SAFE_MODE else 'ASSAULT'}[/]")
    console.print(f"[bold green]Framework Capacity:[/bold green] Depth={settings.MAX_DEPTH}, Concurrency={settings.MAX_CONCURRENT_URL_AGENTS}")
    console.print(f"[bold cyan]Architecture:[/bold cyan] Sequential Pipeline (V2 Architecture)")

    from bugtrace.core.database import get_db_manager
    db = get_db_manager()

    async def _execute_phases():
        nonlocal resume
        from bugtrace.core.ui import dashboard
        from rich.live import Live
        
        # Consistent output directory across phases
        from urllib.parse import urlparse
        domain = urlparse(target).netloc or "unknown"
        if ":" in domain: domain = domain.split(":")[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        common_output_dir = Path(settings.REPORT_DIR) / f"{domain}_{timestamp}"

        if not resume and phase != "manager":
            from bugtrace.utils.janitor import clean_environment
            clean_environment()

        dashboard.reset()
        dashboard.start_keyboard_listener()

        with Live(dashboard, refresh_per_second=4, screen=True):
            dashboard.active = True
            
            # Phase 1: Hunter (Discovery)
            orchestrator = None
            if phase in ["hunter", "all"]:
                # --- RESUME CHECK (V2 Persistence) ---
                try:
                    active_scan_id = db.get_active_scan(target)
                    if active_scan_id and not resume: # Don't ask if --resume already passed flag
                        scan_state_json = db.get_checkpoint(active_scan_id)
                        if scan_state_json:
                            import json
                            state = json.loads(scan_state_json)
                            processed = len(state.get("processed_urls", []))
                            queued = len(state.get("url_queue", []))
                            total = processed + queued
                            pct = int((processed / total * 100)) if total > 0 else 0
                            
                            console.print(f"\n[bold yellow]⚠️  Found UNFINISHED SCAN for {target}[/bold yellow]")
                            console.print(f"   • Scan ID: {active_scan_id}")
                            console.print(f"   • Progress: {processed} analyzed / {total} total (~{pct}%)")
                            console.print(f"   • Queued: {queued} URLs waiting")
                            
                            # Auto-resume for headless operations or CLI convenience
                            console.print("[green]🔄 Auto-resuming detected active scan...[/green]")
                            resume = True
                except Exception as e:
                    # Don't crash if DB is locked or weird
                    console.print(f"[dim]State check warning: {e}[/dim]")

                from bugtrace.core.team import TeamOrchestrator
                orchestrator = TeamOrchestrator(
                    target, 
                    resume=resume, 
                    max_depth=settings.MAX_DEPTH, 
                    max_urls=settings.MAX_URLS, 
                    use_vertical_agents=True,
                    output_dir=common_output_dir
                )
                console.print(f"\n[bold green]🏹 Launching Hunter Phase (Scan ID: {orchestrator.scan_id})[/bold green]")
                await orchestrator.start()
                
                # --- PHASE TRANSITION CLEANUP ---
                from bugtrace.tools.visual.browser import browser_manager
                await browser_manager.stop()

            # Phase 2: Auditor (Audit)
            if phase in ["manager", "all"]:
                from bugtrace.core.validator_engine import ValidationEngine
                sid = scan_id or (orchestrator.scan_id if orchestrator else db.get_active_scan(target))
                
                # V3.5 Fallback: if no active scan, take the latest completed one
                if not sid:
                    sid = db.get_latest_scan_id(target)
                
                # If we didn't run hunter in this process, we might not have common_output_dir defined 
                # if we are running 'audit' command directly.
                out_dir = common_output_dir if 'common_output_dir' in locals() else None

                if not sid:
                    console.print("[red]Error: Could not determine Scan ID for auditing.[/red]")
                    return

                console.print(f"\n[bold yellow]🛡️  Launching Auditor (Validator) Phase (Processing findings for Scan {sid})...[/bold yellow]")
                engine = ValidationEngine(scan_id=sid, output_dir=out_dir)
                await engine.run(continuous=continuous)
                console.print(f"[bold green]✅ Auditor Phase Complete.[/bold green]")
            
            dashboard.active = False
            
            if dashboard.stop_requested:
                console.print("\n[bold red]🛑 Emergency stop requested. Cleaning up and exiting...[/bold red]")
                import os
                import signal
                try:
                    os.killpg(os.getpgrp(), signal.SIGKILL)
                except:
                    import sys
                    sys.exit(1)

    try:
        asyncio.run(_execute_phases())
    except KeyboardInterrupt:
        console.print("\n[yellow]Engagement aborted by user.[/yellow]")
    except Exception as e:
        import traceback
        traceback.print_exc()
        console.print(f"\n[bold red]Fatal Framework Error:[/bold red] {e}")
    finally:
        # Always persist Q-Learning data on exit
        _save_qlearning_data()


def _run_focused_mode(target: str, xss: bool = False, sqli: bool = False, lfi: bool = False, jwt: bool = False, idor: bool = False, ssrf: bool = False, param: str = None):
    """
    Run focused testing mode - bypasses DAST and runs only specified agent.
    Useful for debugging and targeted testing.
    """
    from urllib.parse import urlparse, parse_qs
    
    console.print(f"\n[bold magenta]🎯 FOCUSED TESTING MODE[/bold magenta]")
    console.print(f"[bold green]Target:[/bold green] [cyan]{target}[/cyan]")
    
    # Determine parameters to test
    parsed = urlparse(target)
    if param:
        params = [p.strip() for p in param.split(',')]
        console.print(f"[bold green]Parameters:[/bold green] {', '.join(params)}")
    else:
        # Extract params from URL query string - if none, XSSAgent will discover automatically
        query_params = parse_qs(parsed.query)
        params = list(query_params.keys()) if query_params else []
        if params:
            console.print(f"[bold green]URL Parameters:[/bold green] {', '.join(params)}")
        else:
            console.print(f"[bold green]Parameters:[/bold green] [cyan]Auto-discovery mode[/cyan]")
    
    # Create output directory
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_name = "xss" if xss else ("sqli" if sqli else ("jwt" if jwt else ("lfi" if lfi else ("idor" if idor else "ssrf"))))
    report_dir = Path(settings.REPORT_DIR) / f"focused_{mode_name}_{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold green]Output:[/bold green] {report_dir}")
    console.print("")
    
    async def run_agent():
        from bugtrace.core.ui import dashboard
        dashboard.current_phase = "FOCUSED_TEST"
        
        if xss:
            if params:
                console.print(f"[bold yellow]🔥 Running XSSAgent on param: {', '.join(params)}[/bold yellow]\n")
            else:
                console.print("[bold yellow]🔥 Running XSSAgent (autonomous mode)...[/bold yellow]\n")
            from bugtrace.agents.xss_agent import XSSAgent
            
            # XSSAgent will discover params automatically if not provided
            agent = XSSAgent(target, params if params else None, report_dir)
            result = await agent.run_loop()
            
            return result
            
            return result
            
        elif jwt:
            console.print("[bold yellow]🔑 Running JWTAgent...[/bold yellow]\n")
            from bugtrace.agents.jwt_agent import run_jwt_analysis
            
            # Since JWTAgent is usually event-driven, we just fire the direct analysis helper
            # If the user provided a token via param, use it. Otherwise, warn.
            token = params[0] if params else None
            
            if not token:
                console.print("[bold red]ERROR: For JWT focused mode, you must provide the token via --param 'eyJ...'[/bold red]")
                return {"findings": [], "error": "Token required in --param"}
            
            # Now run_jwt_analysis returns a dict with 'findings'
            return await run_jwt_analysis(token, target) 

            
        elif sqli:
            console.print("[bold yellow]💉 Running SQLMapAgent...[/bold yellow]\n")
            from bugtrace.agents.sqlmap_agent import SQLMapAgent
            
            agent = SQLMapAgent(target, params, report_dir)
            result = await agent.run_loop()
            
            return result
            
        elif lfi:
            console.print("[bold yellow]📁 Running LFIAgent...[/bold yellow]\n")
            from bugtrace.agents.lfi_agent import LFIAgent
            
            agent = LFIAgent(target, params if params else None, report_dir)
            result = await agent.run_loop()
            
            return result
            
        elif idor:
            console.print("[bold yellow]👤 Running IDORAgent...[/bold yellow]\n")
            from bugtrace.agents.idor_agent import IDORAgent
            
            # IDORAgent expects a list of dicts with 'parameter' and 'original_value'
            # If we don't have original values (autonomous mode), we'll pass defaults or dummy
            idor_params = []
            if params:
                for p in params:
                    # In focused mode, we might not have the original value from the URL if it wasn't there
                    # But parse_qs should have caught it if it was in the URL
                    idor_params.append({"parameter": p, "original_value": "1"}) 
            
            agent = IDORAgent(target, idor_params if idor_params else None, report_dir)
            result = await agent.run_loop()
            
            return result
            
        elif ssrf:
            console.print("[bold yellow]🌐 Running SSRFAgent...[/bold yellow]\n")
            from bugtrace.agents.ssrf_agent import SSRFAgent
            
            agent = SSRFAgent(target, params if params else None, report_dir)
            result = await agent.run_loop()
            
            return result
    
    from bugtrace.core.ui import dashboard
    from rich.live import Live
    
    dashboard.reset()
    dashboard.start_keyboard_listener()

    try:
        with Live(dashboard, refresh_per_second=4, screen=True):
            dashboard.active = True
            result = asyncio.run(run_agent())
            dashboard.active = False
            
            if dashboard.stop_requested:
                console.print("\n[bold red]🛑 Emergency stop requested. Cleaning up and exiting...[/bold red]")
                import os
                import signal
                try:
                    os.killpg(os.getpgrp(), signal.SIGKILL)
                except:
                    import sys
                    sys.exit(1)
        
        # Display results
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
                
            # Generate Professional Report
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

    except KeyboardInterrupt:
        console.print("\n[yellow]Test aborted by user.[/yellow]")
    except Exception as e:
        import traceback
        traceback.print_exc()
        console.print(f"\n[bold red]Error:[/bold red] {e}")
    finally:
        # Always persist Q-Learning data on exit
        _save_qlearning_data()


if __name__ == "__main__":
    app()

