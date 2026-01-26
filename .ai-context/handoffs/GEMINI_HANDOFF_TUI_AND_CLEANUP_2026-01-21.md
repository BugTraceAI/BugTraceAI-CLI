# Handoff: TUI Control, State Resilience, and Zombie Process Management

**Date**: January 21, 2026
**Status**: COMPLETED & VERIFIED

## 1. Overview

This update addresses critical user experience and engineering stability issues related to the Terminal User Interface (TUI) and background process management. The primary goals were to enable effective scan termination, ensure a clean UI state for every new scan, and prevent "zombie" processes from lingering after the CLI exits.

## 2. Key Improvements

### 2.1. Non-Blocking Keyboard Listener ('q' to quit, 'p' to pause)

* **File**: `bugtrace/core/ui.py`
* **Change**: Implemented a dedicated background thread in the `Dashboard` class that listens for raw terminal input using `termios` and `tty`.
* **Impact**: Users can now press 'q' at any time to initiate a shutdown. This is more reliable than standard `input()` or signal handlers in a complex Rich-based TUI.

### 2.2. Emergency Hard-Kill Mechanism

* **File**: `bugtrace/__main__.py`
* **Change**: Added logic to verify the `dashboard.stop_requested` flag after the TUI context exits. If true, the system executes `os.killpg(os.getpgrp(), signal.SIGKILL)`.
* **Impact**: This ensures that **all** child processes linked to the main process group—including Go fuzzers, Playwright browsers, and sqlmap instances—are terminated immediately. This prevents the "zombie process" problem where background tools keep running even if the Python CLI stops.

### 2.3. Dashboard State Reset

* **File**: `bugtrace/core/ui.py`
* **Change**: Added a `reset()` method to the `Dashboard` class that clears all internal lists (findings, logs, active tasks) and counters.
* **Impact**: When a new scan starts, the UI now begins with a completely blank slate, preventing confusion caused by seeing data from previous runs.

### 2.4. Enhanced Environment Cleanup (Janitor)

* **File**: `bugtrace/utils/janitor.py`
* **Change**: Updated `clean_environment()` to specifically target and kill the new high-performance Go fuzzers (`go-idor-fuzzer`, `go-ssrf-fuzzer`, etc.).
* **Impact**: Guarantees that no stale scanners are interfering with a fresh scan session.

### 2.5. Graceful Loop Termination

* **Files**: `bugtrace/core/team.py`, `bugtrace/core/validator_engine.py`
* **Change**: Injected `dashboard.stop_requested` checks into the main iterative loops of both the Hunter (TeamOrchestrator) and Auditor (ValidationEngine) phases.
* **Impact**: Allows the framework to stop processing the current queue of URLs or findings as soon as possible when the user requests a stop.

## 3. Verification Scan Results

* **Target**: `https://ginandjuice.shop`
* **Findings Verification**:
  * **IDOR**: The new semantic analysis in the Go fuzzer correctly filtered out false positives caused by dynamic elements.
  * **XSS**: `XSSAgent` successfully utilized Vision AI to confirm executions and assigned correct severity tiers.
* **TUI Verification**:
  * Pressing 'q' during the Hunter phase correctly triggered the shutdown sequence and killed all background processes.
  * Starting a subsequent scan showed a clean dashboard with zero findings/logs from the previous attempt.

## 4. Maintenance Notes

* If new external tools are added to the framework, ensure their executable names are added to `bugtrace/utils/janitor.py` for proper cleanup.
* The keyboard listener uses low-level terminal settings; if the TUI crashes unexpectedly, the terminal might need a `reset` command to restore normal input behavior (though the `Live` context manager usually handles this).
