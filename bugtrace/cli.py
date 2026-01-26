import asyncio
import typer
import click
from typing import Optional
from rich.console import Console
from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.config import settings
from pathlib import Path

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

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    target: Optional[str] = typer.Argument(None, help="The target URL to engage the framework against"),
    safe_mode: Optional[bool] = typer.Option(None, "--safe-mode", help="Override SAFE_MODE setting"),
    resume: bool = typer.Option(False, help="Resume from previous state file"),
    horizontal: bool = typer.Option(False, "--horizontal", help="Use legacy horizontal architecture (not recommended)"),
    # Focused testing modes
    xss: bool = typer.Option(False, "--xss", help="XSS-only mode: Run only XSSAgent for focused testing"),
    sqli: bool = typer.Option(False, "--sqli", help="SQLi-only mode: Run only SQLMapAgent for focused testing"),
    jwt: bool = typer.Option(False, "--jwt", help="JWT-only mode: Run only JWTAgent for focused testing"),
    lfi: bool = typer.Option(False, "--lfi", help="LFI-only mode: Run only LFI detection"),
    param: Optional[str] = typer.Option(None, "--param", "-p", help="Parameter to test (for focused modes)")
):
    """
    BugtraceAI: Autonomous Multi-Agent Security Framework
    
    Examples:
        bugtraceai-cli https://target.com                  # Full scan
        bugtraceai-cli https://target.com --xss            # XSS-only mode
        bugtraceai-cli https://target.com --xss -p search  # XSS on specific param
        bugtraceai-cli https://target.com --sqli           # SQLi-only mode
        bugtraceai-cli https://target.com --jwt            # JWT-only mode (Token Analysis)
    """
    if ctx.invoked_subcommand:
        return

    if not target:
        console.print("[bold red]Error:[/bold red] Target URL is required to engage the framework.")
        raise typer.Exit(code=1)

    # 0. The Janitor (Environment Purge)
    from bugtrace.utils.janitor import clean_environment
    clean_environment()

    # Use configuration file values by default, allow minor CLI overrides
    if safe_mode is not None:
        settings.SAFE_MODE = safe_mode
    
    # --- FOCUSED TESTING MODE ---
    if xss or sqli or lfi or jwt:
        _run_focused_mode(target, xss=xss, sqli=sqli, lfi=lfi, jwt=jwt, param=param)
        return
    
    boot_success = True

    console.print(f"\n[bold green]Deploying Framework against:[/bold green] [cyan]{target}[/cyan]")
    console.print(f"[bold green]Security Level:[/bold green] [{'green' if settings.SAFE_MODE else 'red'}]{'SAFE' if settings.SAFE_MODE else 'ASSAULT'}[/]")
    console.print(f"[bold green]Framework Capacity:[/bold green] Depth={settings.MAX_DEPTH}, Concurrency={settings.MAX_CONCURRENT_URL_AGENTS}")
    # V4 REACTOR ARCHITECTURE (Advanced Event-Driven Engine)
    console.print(f"[bold cyan]Architecture:[/bold cyan] Event-Driven Reactive Swarm (V4)")
    
    try:
        from bugtrace.core.reactor import Reactor
        from bugtrace.core.job_manager import JobManager
        
        # Deploy Reactor
        reactor = Reactor(target, resume=resume)
        
        # Run the Loop
        asyncio.run(reactor.run())
        
        # Post-Processing: Report Generation
        console.print("\n[bold cyan]📊 Generating Final Report...[/bold cyan]")
        
        # Query Jobs DB for findings
        import sqlite3
        import json
        conn = sqlite3.connect("state/jobs.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM jobs WHERE status='COMPLETED' AND result IS NOT NULL")
        jobs = cursor.fetchall()
        
        all_findings = []
        processed_urls = set()
        
        for j in jobs:
            try:
                res = json.loads(j['result'])
                if 'findings' in res:
                    all_findings.extend(res['findings'])
                if j['type'] == 'ANALYSIS':
                    processed_urls.add(j['target'])
            except:
                pass
                
        conn.close()
        
        # Report
        from bugtrace.core.ui import dashboard
        for f in all_findings:
            if isinstance(f, str):
                f = {"type": f, "url": target, "severity": "Unknown"}
                
            sev = f.get('severity', 'HIGH')
            loc = f.get('url', 'Unknown')
            # Extract clean type string or dict value
            vuln_type = f.get('type')
            if isinstance(vuln_type, dict): vuln_type = "Vulnerability"
            dashboard.add_finding(str(vuln_type), loc, sev)
            
        dashboard.save_report()

        console.print(f"[bold green]✅ Mission Complete. Scanned {len(processed_urls)} URLs. Found {len(all_findings)} issues.[/bold green]")
        console.print(f"Report saved to: {settings.REPORT_DIR}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Engagement aborted by user.[/yellow]")
    except Exception as e:
        import traceback
        traceback.print_exc()
        console.print(f"\n[bold red]Fatal Framework Error:[/bold red] {e}")
    finally:
        # Always persist Q-Learning data on exit (graceful or not)
        _save_qlearning_data()


def _run_focused_mode(target: str, xss: bool = False, sqli: bool = False, lfi: bool = False, jwt: bool = False, param: str = None):
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
    mode_name = "xss" if xss else ("sqli" if sqli else ("jwt" if jwt else "lfi"))
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
            console.print("[bold yellow]📁 Running LFI Detection...[/bold yellow]\n")
            # TODO: Add LFIAgent when available
            console.print("[red]LFI-only mode not yet implemented[/red]")
            return {"findings": []}
    
    try:
        result = asyncio.run(run_agent())
        
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

