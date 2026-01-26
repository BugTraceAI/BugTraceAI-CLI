# 🚀 BugTraceAI - Quick Start & Usage Guide

**STOP! Read this before running the tool.**
Use the standard CLI wrapper `./bugtraceai-cli`. Do not run `python -m bugtrace` directly unless debugging.

---

## 1. Standard Scan (Default)

The easiest way to run BugTraceAI. This automatically performs a **Full Scan** (Discovery + Hunting + Validation).

**Syntax:**

```bash
./bugtraceai-cli <TARGET_URL>
```

**Example:**

```bash
./bugtraceai-cli "https://ginandjuice.shop"
```

*Note: The script automatically detects the URL and launches the full pipeline.*

### Fresh Start (Nuke Everything)

If you want to ensure a **completely clean slate** (delete database, all logs, and previous reports):

```bash
./bugtraceai-cli --clean "https://ginandjuice.shop"
```

**Configuration**:

- Edit `bugtraceaicli.conf` to adjust threads/concurrency.
- Default `MAX_URLS = 0` (Unlimited) or set a high limit.

---

## 2. Single URL Scan (Targeted Debugging)

To scan **ONLY ONE** specific URL (skipping deep crawling and asset discovery) for vulnerability verification:

1. **Edit Config**: Open `bugtraceaicli.conf` and set:

   ```ini
   MAX_URLS = 1
   ```

2. **Run Command**:

   ```bash
   ./bugtraceai-cli "https://example.com/item?id=1"
   ```

**Why?** This forces the "Hunter" phase to stop after the first target, ensuring focused testing on the specific parameter.

---

## 3. Validation Only (Auditor Mode)

If a scan hung or was interrupted, but finding are in the DB (`PENDING_VALIDATION`), you can resume just the validation phase:

```bash
# resume validation for findings in DB associated with this target
./bugtraceai-cli audit "https://example.com"
```

---

## 4. Reporting Only

To regenerate reports (HTML/JSON) from existing DB data without re-scanning or re-validating:

*Currently requires a helper script, or forcing the audit phase which triggers reporting at the end.*

---

## 5. Training Dojo (Local Testing)

To run against the local vulnerable app (Dojo):

1. **Start Dojo**:

   ```bash
   python3 applications/dvwa/app.py --port 5050
   ```

2. **Scan**:

   ```bash
   ./bugtraceai-cli "http://127.0.0.1:5050"
   ```

---

## ⚠️ Common Pitfalls (Do NOT do this)

- ❌ **Don't use `--single-url` flag**: It doesn't exist anymore. Use `MAX_URLS=1` in config.
- ❌ **Don't run with `python3 bugtrace/main.py`**: Values PYTHONPATH correctly setup by the shell script wrapper.
- ❌ **Don't forget to clean up**: If a scan crashes hard, run `pkill -f chrome` to ensure no zombies lock the port. (Though the tool now does this auto-magically on start).
