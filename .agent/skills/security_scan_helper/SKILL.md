---
name: security_scan_helper
description: Assists in configuring and launching BugTraceAI security scans according to V5 architecture best practices. Use this when the user wants to "run a scan", "test the app", or "check for vulnerabilities".
---

# Security Scan Helper Skill

This skill ensures that you launch security scans using the correct parameters and environment configurations for the "Reactor V5" architecture.

## 1. Scan Profiles

Determine which profile the user needs:

### A. Quick Smoke Test (Development)

*Target*: Fast feedback loop.
*Config*:

- `MAX_URLS = 5`
- `CONCURRENCY = 2`
*Command*:

```bash
python3 main.py --url [TARGET_URL] --scan-type quick
```

### B. Full Deep Scan (Validation)

*Target*: Comprehensive coverage.
*Config*:

- `MAX_URLS = 50` (or more)
- `CONCURRENCY = 5`
*Command*:

```bash
python3 main.py --url [TARGET_URL] --scan-type full
```

### C. Dojo Verification (Benchmarks)

*Target*: Validating against the internal vulnerable app (Dojo).
*Config*: Specialized for local testing.
*Command*:

```bash
# Ensure Dojo is running first!
python3 main.py --url http://127.0.0.1:5150 --scan-type full
```

## 2. Pre-Flight Checks

Before running a scan command, ALWAYS:

1. **Check Environment**: Ensure `.env` exists and contains necessary keys (e.g., `OPENAI_API_KEY` or `GEMINI_API_KEY` if Vision AI is active).
2. **Clean State**: If requested, clean previous reports:

   ```bash
   rm -rf reports/* logs/*
   ```

## 3. Post-Scan Verification

After the scan command finishes:

1. **Check Logs**: Read `logs/bugtrace.log` for "CRITICAL" errors.
2. **Verify Reports**: valid correct generation of `reports/final_report.md` and `reports/report.html`.

## 4. Instructions for the Agent

1. Ask the user for the **Target URL** if not provided.
2. Ask for the **Scan Profile** (Quick vs Full) if not obvious.
3. Use `run_command` to execute the scan.
4. Use `read_terminal` or `view_file` to monitor progress.
