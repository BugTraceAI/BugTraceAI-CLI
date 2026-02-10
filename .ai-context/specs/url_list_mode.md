# URL List Mode - Technical Specification

> **Version**: 3.2.0
> **Status**: ✅ Implemented
> **Date**: 2026-02-02
> **Author**: BugTraceAI Team

---

## 📋 Overview

**URL List Mode** allows BugTraceAI to accept a **predefined list of URLs** for scanning, bypassing the GoSpider crawling phase entirely. This enables:

- ✅ **6x faster Phase 1** (reconnaissance)
- ✅ **Precise targeting** of specific endpoints
- ✅ **Integration** with external tools (Burp, katana, waybackurls)
- ✅ **Controlled rescans** of high-value URLs

---

## 🎯 Problem Statement

### Before URL List Mode

**Workflow**:
```
User → BugTraceAI → GoSpider (crawls entire site) → Scan 100+ URLs
```

**Limitations**:
- ❌ GoSpider takes ~30s for discovery
- ❌ Cannot integrate URLs from Burp Suite
- ❌ No control over which URLs to scan
- ❌ Difficult to rescan specific endpoints

### After URL List Mode

**Workflow**:
```
User → Create urls.txt → BugTraceAI -ul urls.txt → Scan ONLY those URLs
```

**Benefits**:
- ✅ Phase 1 takes ~5s (only Nuclei tech detection)
- ✅ Direct integration with external tools
- ✅ Full control over scan scope
- ✅ Fast rescans of critical endpoints

---

## 🛠️ Implementation

### CLI Interface

**New Parameter**: `-ul <file>`

```bash
# Full scan with URL list
./bugtraceai-cli https://example.com -ul urls.txt

# Hunter phase only
./bugtraceai-cli scan https://example.com -ul urls.txt

# Combined with other flags
./bugtraceai-cli https://example.com -ul urls.txt --clean --xss
```

**File**: `bugtrace/__main__.py:74,100`

```python
@app.command(name="full")
def full_scan(
    target: str = typer.Argument(...),
    url_list_file: Optional[str] = typer.Option(
        None, "-ul",
        help="File with URLs to scan (bypasses GoSpider, one URL per line)"
    ),
    # ... other params
):
    _run_pipeline(target, phase="all", url_list_file=url_list_file, ...)
```

### URL Loading & Validation

**File**: `bugtrace/__main__.py:198-257`

```python
def _load_url_list(file_path: str, target: str) -> list:
    """
    Load URLs from file, one per line.
    Filters URLs to only include those from the target domain.
    Ignores empty lines and comments (#).
    """
    # 1. Validate file exists
    if not Path(file_path).exists():
        raise FileNotFoundError(...)

    # 2. Extract target domain
    target_domain = urlparse(target).netloc

    # 3. Parse file line by line
    for line in f:
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue

        # Validate URL format
        parsed = urlparse(line)
        if not parsed.scheme or not parsed.netloc:
            console.print("[yellow]Warning: Invalid URL[/yellow]")
            continue

        # Filter by domain
        if parsed.netloc == target_domain:
            urls.append(line)
        else:
            console.print(f"[dim]Skipping different domain: {line}[/dim]")

    # 4. Ensure at least one valid URL
    if not urls:
        raise ValueError(f"No valid URLs found matching {target_domain}")

    return urls
```

**Validation Rules**:
1. ✅ File must exist
2. ✅ Each line must be a valid URL (scheme + netloc)
3. ✅ URL domain must match target domain
4. ✅ At least one valid URL required
5. ✅ Comments (`#`) and empty lines ignored

### TeamOrchestrator Integration

**File**: `bugtrace/core/team.py:79`

```python
class TeamOrchestrator:
    def __init__(
        self,
        target: str,
        # ... other params
        url_list: Optional[List[str]] = None  # NEW parameter
    ):
        self.target = target
        self.url_list_provided = url_list  # Store for Phase 1
        # ...
```

### Reconnaissance Logic

**File**: `bugtrace/core/team.py:1206-1250`

```python
async def _run_reconnaissance(self, dashboard, recon_dir) -> list:
    """Run reconnaissance phase and return discovered URLs."""

    # Resume mode (existing)
    if self.resume and self.url_queue:
        return self.url_queue

    # ========== URL List Mode (NEW) ==========
    if self.url_list_provided:
        dashboard.log(f"📋 URL List Mode: Using {len(self.url_list_provided)} URLs", "INFO")
        dashboard.log("⏩ Bypassing GoSpider", "INFO")

        # Run Nuclei ONLY on main target
        nuclei_agent = NucleiAgent(self.target, recon_dir)
        self.tech_profile = await nuclei_agent.run()

        # Use provided URLs directly
        urls_to_scan = self.url_list_provided
        await self._scan_for_tokens(urls_to_scan)

        return self._normalize_urls(urls_to_scan)

    # ========== Normal Mode (GoSpider) ==========
    # Nuclei + GoSpider execution
    # ...
```

**Flow Changes**:

| Step | Normal Mode | URL List Mode |
|------|-------------|---------------|
| 1. Nuclei | ✅ Runs on target | ✅ Runs on target |
| 2. GoSpider | ✅ Crawls entire site | ❌ **BYPASSED** |
| 3. URLs | From GoSpider (~50-100) | From file (5-50) |
| 4. JWT Scan | ✅ Runs | ✅ Runs |
| 5. Normalization | ✅ Runs | ✅ Runs |

---

## 📝 File Format Specification

### Basic Format

```txt
# Comments start with #
# One URL per line

https://example.com/api/users
https://example.com/api/products
https://example.com/search?q=test
```

### Advanced Format

```txt
# API Endpoints
https://example.com/api/v1/users
https://example.com/api/v1/products
https://example.com/api/v1/auth

# Pages with parameters (high priority)
https://example.com/product?id=1
https://example.com/search?q=test&category=books

# Admin panels
https://example.com/admin/dashboard
https://example.com/admin/settings

# URLs from different domains (filtered automatically)
https://other-domain.com/api  # This will be skipped with warning
```

### Parsing Rules

1. **Comments**: Lines starting with `#` are ignored
2. **Empty Lines**: Blank lines are ignored
3. **Whitespace**: Leading/trailing whitespace is trimmed
4. **URL Validation**:
   - Must have scheme (`http://` or `https://`)
   - Must have netloc (domain)
   - Invalid URLs logged with warning
5. **Domain Filtering**:
   - Only URLs matching target domain are processed
   - Other domains logged and skipped
   - No cross-domain scanning allowed

---

## 🧪 Example Use Cases

### 1. Burp Suite Integration

**Export from Burp**:
```
Proxy → HTTP History → Select URLs → Copy URLs → Save to file
```

**Scan with BugTraceAI**:
```bash
./bugtraceai-cli https://target.com -ul burp_urls.txt
```

### 2. Targeted Rescan

**Filter critical endpoints**:
```bash
# Extract only URLs with parameters
grep "?" all_discovered_urls.txt > critical_params.txt

# Scan only those
./bugtraceai-cli https://target.com -ul critical_params.txt
```

### 3. API Endpoint Testing

**Create API list**:
```bash
cat > api_endpoints.txt <<EOF
https://api.example.com/v1/users
https://api.example.com/v1/auth/login
https://api.example.com/v1/auth/logout
https://api.example.com/v1/products
https://api.example.com/v1/orders
EOF

./bugtraceai-cli https://api.example.com -ul api_endpoints.txt
```

### 4. External Crawler Integration

**With katana**:
```bash
katana -u https://target.com -silent > discovered.txt
./bugtraceai-cli https://target.com -ul discovered.txt
```

**With waybackurls**:
```bash
waybackurls target.com > wayback.txt
./bugtraceai-cli https://target.com -ul wayback.txt
```

**With gau (Get All URLs)**:
```bash
gau target.com > gau_urls.txt
./bugtraceai-cli https://target.com -ul gau_urls.txt
```

### 5. CI/CD Regression Testing

**Fixed URL set for automated testing**:
```bash
# regression_urls.txt (checked into repo)
https://staging.example.com/api/users
https://staging.example.com/api/products
https://staging.example.com/checkout

# CI pipeline
./bugtraceai-cli https://staging.example.com -ul regression_urls.txt --json
```

---

## 📊 Performance Metrics

### Phase 1 Duration

| Mode | Nuclei | GoSpider | Total | Improvement |
|------|--------|----------|-------|-------------|
| **Normal** | ~5s | ~30s | ~35s | - |
| **URL List** | ~5s | ⏩ 0s | ~5s | **7x faster** |

### Resource Usage

| Resource | Normal Mode | URL List Mode |
|----------|-------------|---------------|
| **Docker containers** | 2 (Nuclei + GoSpider) | 1 (Nuclei only) |
| **Network requests** | ~100-500 | ~10-20 |
| **Memory** | ~300MB | ~100MB |
| **Disk I/O** | High (crawl results) | Low (read file) |

### URL Processing

| Metric | Normal | URL List |
|--------|--------|----------|
| **URLs discovered** | 50-500 | N/A |
| **URLs provided** | N/A | 5-100 |
| **URLs scanned** | All discovered | All valid from file |
| **Precision** | Variable | High |

---

## 🔒 Security Considerations

### Domain Isolation

**Protection**: URLs from different domains are automatically filtered

**Example**:
```txt
# urls.txt
https://target.com/api        ← ✅ Processed
https://malicious.com/api     ← ❌ Filtered
https://target.com/admin      ← ✅ Processed
```

**Output**:
```
✅ Loaded 2 URLs from urls.txt
⚠️  Filtered 1 URLs from different domains
Skipping URL from different domain: https://malicious.com/api
```

**Rationale**: Prevents accidental scanning of unintended targets

### File Path Validation

- ✅ Validates file exists before processing
- ✅ Proper error handling for file read errors
- ✅ Line-by-line parsing (no arbitrary code execution)

### Input Sanitization

- ✅ URL validation via `urllib.parse.urlparse()`
- ✅ Scheme and netloc required
- ✅ Domain matching enforced
- ✅ No shell injection risk (file read only)

---

## 🧪 Testing

### Unit Tests

**File**: `tests/unit/test_url_list_mode.py`

```python
def test_load_url_list_valid():
    """Test loading valid URL list."""
    urls = _load_url_list("valid_urls.txt", "https://example.com")
    assert len(urls) == 3
    assert all("example.com" in url for url in urls)

def test_load_url_list_filters_other_domains():
    """Test that other domains are filtered."""
    urls = _load_url_list("mixed_urls.txt", "https://example.com")
    assert "other-domain.com" not in str(urls)

def test_load_url_list_file_not_found():
    """Test error handling for missing file."""
    with pytest.raises(FileNotFoundError):
        _load_url_list("missing.txt", "https://example.com")

def test_load_url_list_no_valid_urls():
    """Test error when no valid URLs match domain."""
    with pytest.raises(ValueError, match="No valid URLs found"):
        _load_url_list("wrong_domain_urls.txt", "https://example.com")
```

### Integration Tests

```bash
# Test 1: Normal execution
echo "https://ginandjuice.shop/api/products" > test_urls.txt
./bugtraceai-cli https://ginandjuice.shop -ul test_urls.txt

# Test 2: Mixed domains (should filter)
cat > mixed.txt <<EOF
https://ginandjuice.shop/api
https://other.com/api
EOF
./bugtraceai-cli https://ginandjuice.shop -ul mixed.txt

# Test 3: Invalid file
./bugtraceai-cli https://ginandjuice.shop -ul nonexistent.txt
# Expected: Error message

# Test 4: Comments and empty lines
cat > commented.txt <<EOF
# API endpoints
https://ginandjuice.shop/api/products

# More endpoints
https://ginandjuice.shop/api/cart
EOF
./bugtraceai-cli https://ginandjuice.shop -ul commented.txt
```

---

## 🔧 Implementation Checklist

- [x] CLI argument `-ul` added to `scan` and `full` commands
- [x] `_load_url_list()` helper function implemented
- [x] Domain filtering logic
- [x] File validation and error handling
- [x] `TeamOrchestrator` constructor accepts `url_list` parameter
- [x] `_run_reconnaissance()` handles URL list mode
- [x] GoSpider bypass logic
- [x] Nuclei still runs on main target
- [x] Dashboard logs indicate URL list mode
- [x] Example file `example_urls.txt` created
- [x] Documentation updated in `.ai-context/guides/quickstart.md`
- [x] Documentation updated in `.ai-context/architecture/phases/pipeline_phases.md`
- [x] Technical spec created (this document)

---

## 📚 Related Documentation

- **User Guide**: `.ai-context/guides/quickstart.md` - Section 3: URL List Mode
- **Architecture**: `.ai-context/architecture/phases/pipeline_phases.md` - Fase 1 modes
- **Implementation**:
  - CLI: `bugtrace/__main__.py:74,100,198-257`
  - Orchestrator: `bugtrace/core/team.py:79,1206-1250`

---

## 🚀 Future Enhancements

### Potential Improvements

1. **JSON Format Support**:
   ```json
   {
     "urls": [
       {"url": "https://example.com/api", "priority": "high"},
       {"url": "https://example.com/admin", "priority": "medium"}
     ]
   }
   ```

2. **URL Pattern Expansion**:
   ```txt
   https://example.com/product?id={1..100}
   # Expands to 100 URLs
   ```

3. **Cross-Domain Mode**:
   ```bash
   ./bugtraceai-cli https://example.com -ul urls.txt --allow-cross-domain
   ```

4. **URL Deduplication**:
   - Remove duplicate URLs from file
   - Normalize query parameter order
   - Strip unnecessary tracking parameters

5. **Integration Presets**:
   ```bash
   ./bugtraceai-cli --import-burp burp_state.json
   ./bugtraceai-cli --import-zap zap_session.xml
   ```

---

## 📝 Changelog

### v3.2.0 (2026-02-02)
- ✅ Initial implementation of URL List Mode
- ✅ CLI parameter `-ul` added
- ✅ Domain filtering implemented
- ✅ GoSpider bypass logic
- ✅ Documentation completed

---

**Maintained by**: BugTraceAI Team
**Last Updated**: 2026-02-02
**Status**: Production Ready ✅
