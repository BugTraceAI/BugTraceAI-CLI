"""
Instance lock module for BugTraceAI.

Detects if another instance is already running and prompts the user
to either close it or continue anyway.
"""

import os
import sys
import signal
from pathlib import Path
from typing import Optional, Tuple
from rich.console import Console

from bugtrace.core.config import settings


console = Console()

# Lock file location - stored in logs directory
LOCK_FILE_NAME = ".bugtrace.lock"


def get_lock_file_path() -> Path:
    """Get the path to the lock file."""
    # Ensure logs directory exists
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
    return settings.LOG_DIR / LOCK_FILE_NAME


def read_lock_file() -> Optional[Tuple[int, str]]:
    """
    Read the lock file and return (pid, command) if it exists.
    Returns None if lock file doesn't exist or is invalid.
    """
    lock_path = get_lock_file_path()
    if not lock_path.exists():
        return None

    try:
        content = lock_path.read_text().strip()
        lines = content.split('\n')
        if len(lines) >= 2:
            pid = int(lines[0])
            command = lines[1]
            return (pid, command)
        elif len(lines) == 1:
            pid = int(lines[0])
            return (pid, "unknown")
    except (ValueError, IOError):
        # Invalid lock file - remove it
        try:
            lock_path.unlink()
        except Exception:
            pass
        return None

    return None


def is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        # On Unix, sending signal 0 checks if process exists
        os.kill(pid, 0)
        return True
    except OSError:
        return False
    except Exception:
        return False


def write_lock_file(command: str = "") -> bool:
    """
    Write the current PID to the lock file.
    Returns True on success, False on failure.
    """
    lock_path = get_lock_file_path()
    try:
        current_pid = os.getpid()
        lock_path.write_text(f"{current_pid}\n{command}")
        return True
    except Exception as e:
        console.print(f"[dim]Warning: Could not create lock file: {e}[/dim]")
        return False


def remove_lock_file():
    """Remove the lock file (called on clean exit)."""
    lock_path = get_lock_file_path()
    try:
        if lock_path.exists():
            # Only remove if it's our PID
            lock_info = read_lock_file()
            if lock_info and lock_info[0] == os.getpid():
                lock_path.unlink()
    except Exception:
        pass


def terminate_other_instance(pid: int) -> bool:
    """
    Attempt to terminate another BugTraceAI instance.
    Returns True if successful, False otherwise.
    """
    try:
        # First try SIGTERM (graceful shutdown)
        os.kill(pid, signal.SIGTERM)

        # Wait a bit for graceful shutdown
        import time
        for _ in range(10):  # Wait up to 5 seconds
            time.sleep(0.5)
            if not is_process_running(pid):
                return True

        # If still running, force kill
        if is_process_running(pid):
            console.print("[yellow]Process didn't stop gracefully, forcing shutdown...[/yellow]")
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            return not is_process_running(pid)

        return True
    except PermissionError:
        console.print("[red]Permission denied: Cannot terminate the other instance.[/red]")
        console.print("[dim]Try running: kill {pid}[/dim]")
        return False
    except Exception as e:
        console.print(f"[red]Failed to terminate process: {e}[/red]")
        return False


def check_existing_instance() -> Optional[Tuple[int, str]]:
    """
    Check if another BugTraceAI instance is running.
    Returns (pid, command) if running, None otherwise.
    """
    lock_info = read_lock_file()
    if lock_info is None:
        return None

    pid, command = lock_info

    # Check if that process is still running
    if is_process_running(pid):
        # Verify it's actually BugTraceAI (not a recycled PID)
        try:
            # On Linux, check /proc/{pid}/cmdline
            cmdline_path = Path(f"/proc/{pid}/cmdline")
            if cmdline_path.exists():
                cmdline = cmdline_path.read_bytes().decode('utf-8', errors='ignore')
                if 'bugtrace' not in cmdline.lower():
                    # PID was recycled - not our process
                    return None
        except Exception:
            pass  # If we can't verify, assume it's our process

        return (pid, command)

    # Process no longer running - clean up stale lock
    try:
        get_lock_file_path().unlink()
    except Exception:
        pass

    return None


def prompt_instance_conflict(pid: int, command: str) -> str:
    """
    Prompt the user about the existing instance.
    Returns: 'close', 'continue', or 'abort'
    """
    console.print(f"\n[bold yellow]{'='*60}[/bold yellow]")
    console.print(f"[bold yellow]  WARNING: Another BugTraceAI instance detected![/bold yellow]")
    console.print(f"[bold yellow]{'='*60}[/bold yellow]\n")
    console.print(f"  [cyan]PID:[/cyan] {pid}")
    if command and command != "unknown":
        console.print(f"  [cyan]Command:[/cyan] {command}")
    console.print("")
    console.print("  Running multiple instances can cause:")
    console.print("    [dim]- Database conflicts[/dim]")
    console.print("    [dim]- Port conflicts (CDP, API)[/dim]")
    console.print("    [dim]- Resource contention[/dim]")
    console.print("")

    console.print("  What would you like to do?")
    console.print("    [bold green]1)[/bold green] Close the other instance and continue")
    console.print("    [bold yellow]2)[/bold yellow] Continue anyway (not recommended)")
    console.print("    [bold red]3)[/bold red] Abort this launch")
    console.print("")

    try:
        choice = console.input("  [bold]Enter choice (1/2/3):[/bold] ").strip()

        if choice == "1":
            return "close"
        elif choice == "2":
            return "continue"
        else:
            return "abort"
    except (KeyboardInterrupt, EOFError):
        return "abort"


def acquire_instance_lock(command: str = "") -> bool:
    """
    Main entry point: Check for existing instance and handle conflicts.

    Returns True if we should proceed, False if we should abort.
    """
    # Check for existing instance
    existing = check_existing_instance()

    if existing:
        pid, old_command = existing
        choice = prompt_instance_conflict(pid, old_command)

        if choice == "close":
            console.print(f"\n[yellow]Closing instance (PID {pid})...[/yellow]")
            if terminate_other_instance(pid):
                console.print("[green]Previous instance closed.[/green]\n")
                # Small delay to ensure port release etc.
                import time
                time.sleep(0.5)
            else:
                console.print("[red]Could not close the other instance.[/red]")
                return False
        elif choice == "continue":
            console.print("\n[yellow]Continuing with multiple instances...[/yellow]")
            console.print("[dim]Warning: You may experience conflicts.[/dim]\n")
            # Don't create a new lock file - let both run
            return True
        else:  # abort
            console.print("\n[red]Aborting launch.[/red]")
            return False

    # No conflict - write our lock file
    write_lock_file(command)

    # Register cleanup on exit
    import atexit
    atexit.register(remove_lock_file)

    return True
