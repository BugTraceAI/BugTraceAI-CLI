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

## 3. URL List Mode (Bypass GoSpider)

**NEW in v3.2:** Scan a **specific list of URLs** without crawling. Perfect for integration with Burp Suite, katana, waybackurls, or targeted rescans.

### Quick Start

1. **Create URL list file** (one URL per line):

   ```bash
   cat > my_urls.txt <<EOF
   https://ginandjuice.shop/api/products
   https://ginandjuice.shop/product?productId=1
   https://ginandjuice.shop/search?q=test
   EOF
   ```

2. **Run scan with `-ul` flag**:

   ```bash
   ./bugtraceai-cli https://ginandjuice.shop -ul my_urls.txt
   ```

### What Happens

```
Phase 1: RECONNAISSANCE
├─ Nuclei → Tech detection ONLY on ginandjuice.shop ✅
├─ GoSpider → BYPASSED ⏩ (saves ~25s)
└─ URLs loaded from my_urls.txt → Phase 2

Phase 2-6: Normal pipeline with YOUR URLs
```

### File Format

```txt
# Comments start with #
# One URL per line

# API endpoints
https://example.com/api/users?id=1
https://example.com/api/products

# Pages with parameters (high priority)
https://example.com/search?q=test

# Admin panels
https://example.com/admin/dashboard
```

**Rules:**
- ✅ One URL per line
- ✅ Comments with `#`
- ✅ Empty lines ignored
- ⚠️ Only URLs from **same domain** as target are processed
- ❌ URLs from other domains are filtered with warning

### Use Cases

**Integration with Burp Suite:**
```bash
# Export URLs from Burp → urls.txt
./bugtraceai-cli https://target.com -ul urls.txt
```

**Rescan critical endpoints:**
```bash
# Filter only URLs with parameters
grep "?" all_urls.txt > critical.txt
./bugtraceai-cli https://target.com -ul critical.txt
```

**With other crawlers:**
```bash
# katana
katana -u https://target.com -silent > discovered.txt
./bugtraceai-cli https://target.com -ul discovered.txt

# waybackurls
waybackurls target.com > wayback.txt
./bugtraceai-cli https://target.com -ul wayback.txt
```

**API endpoint testing:**
```bash
cat > api_endpoints.txt <<EOF
https://api.example.com/v1/users
https://api.example.com/v1/auth
https://api.example.com/v1/products
EOF
./bugtraceai-cli https://api.example.com -ul api_endpoints.txt
```

### Performance

| Metric | Normal Mode | URL List Mode |
|--------|-------------|---------------|
| Phase 1 Duration | ~30s (GoSpider) | ~5s (Nuclei only) |
| Speed Improvement | - | **6x faster** |
| URLs Processed | ~50-100 (discovered) | 5-50 (your choice) |
| Precision | Variable | **High** (targeted) |

### Example Output

```
✅ Loaded 7 URLs from my_urls.txt
⚠️  Filtered 1 URLs from different domains
🏹 Launching Hunter Phase (Scan ID: 123) - URL List Mode (7 URLs)
📋 URL List Mode: Using 7 provided URLs
⏩ Bypassing GoSpider (list provided)
[Recon] Tech Profile: 2 frameworks detected on https://ginandjuice.shop
```

### Error Handling

**File not found:**
```bash
$ ./bugtraceai-cli https://example.com -ul missing.txt
Error loading URL list: URL list file not found: missing.txt
```

**No valid URLs:**
```bash
$ cat > wrong_domain.txt <<EOF
https://other-domain.com/api
EOF
$ ./bugtraceai-cli https://example.com -ul wrong_domain.txt
Skipping URL from different domain: https://other-domain.com/api
Error loading URL list: No valid URLs found in wrong_domain.txt matching domain example.com
```

---

## 4. Validation Only (Auditor Mode)

If a scan hung or was interrupted, but finding are in the DB (`PENDING_VALIDATION`), you can resume just the validation phase:

```bash
# resume validation for findings in DB associated with this target
./bugtraceai-cli audit "https://example.com"
```

---

## 5. Reporting Only

To regenerate reports (HTML/JSON) from existing DB data without re-scanning or re-validating:

*Currently requires a helper script, or forcing the audit phase which triggers reporting at the end.*

---

## 6. Training Dojo (Local Testing)

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
