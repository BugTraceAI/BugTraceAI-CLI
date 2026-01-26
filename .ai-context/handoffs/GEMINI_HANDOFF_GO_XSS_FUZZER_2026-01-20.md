# GEMINI HANDOFF: Go XSS Payload Fuzzer

**Date:** 2026-01-20  
**Priority:** HIGH  
**Estimated Time:** 3-4 days  
**Scope:** Create a high-performance Go tool for XSS payload testing

---

## 🎯 OBJETIVO

Crear un fuzzer de payloads XSS en **Go** que sea ~100x más rápido que la implementación actual en Python. Esta herramienta será llamada como subprocess desde el `XSSAgent` de Python.

### Por qué Go

- Goroutines: 1000+ requests concurrentes sin overhead
- HTTP client nativo muy eficiente
- Compilado: no hay startup time de intérprete
- Integrable via subprocess (stdout JSON)

---

## 📊 IMPACTO ESPERADO

| Métrica | Python Actual | Go Propuesto | Mejora |
|---------|---------------|--------------|--------|
| Payloads/segundo | 5-10 | 500-1000 | 100x |
| 100 URLs × 50 payloads | ~17 min | ~10-20 seg | 50-100x |
| Memoria | ~500MB | ~50MB | 10x |
| Concurrencia | ~50 conn | ~1000 conn | 20x |

---

## 📁 ESTRUCTURA DEL PROYECTO

```
tools/go-xss-fuzzer/
├── main.go              # Entry point, CLI args
├── fuzzer/
│   ├── fuzzer.go        # Core fuzzing logic
│   ├── payloads.go      # Payload management
│   └── detector.go      # Reflection detection
├── models/
│   └── result.go        # JSON output structures
├── payloads/
│   └── xss_payloads.txt # Default payload list
├── go.mod
├── go.sum
└── Makefile             # Build targets
```

---

## 📋 ESPECIFICACIÓN TÉCNICA

### 1. CLI Interface

```bash
# Uso básico
./go-xss-fuzzer -u "https://target.com/search?q=FUZZ" -p payloads.txt

# Con opciones
./go-xss-fuzzer \
    -u "https://target.com/search?q=FUZZ" \
    -p payloads.txt \
    -c 100 \                    # Concurrencia (goroutines)
    -t 5 \                      # Timeout por request (segundos)
    -H "Cookie: session=abc" \  # Headers adicionales
    -proxy "http://127.0.0.1:8080" \
    --json                      # Output JSON (default)
```

### 2. Input Format

**Opción A: URL con FUZZ marker**

```bash
-u "https://target.com/search?q=FUZZ"
```

**Opción B: Stdin JSON (para batch processing)**

```json
{
    "targets": [
        {"url": "https://target.com/search", "param": "q"},
        {"url": "https://target.com/page", "param": "id"}
    ],
    "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
}
```

### 3. Output Format (JSON stdout)

```json
{
    "metadata": {
        "target": "https://target.com/search?q=",
        "param": "q",
        "total_payloads": 50,
        "total_requests": 50,
        "duration_ms": 1234,
        "requests_per_second": 40.5
    },
    "reflections": [
        {
            "payload": "<script>alert(1)</script>",
            "reflected": true,
            "encoded": false,
            "context": "html_text",
            "response_length": 4521,
            "status_code": 200
        },
        {
            "payload": "<img src=x onerror=alert(1)>",
            "reflected": true,
            "encoded": true,
            "encoding_type": "html_entities",
            "context": "attribute_value",
            "response_length": 4530,
            "status_code": 200
        }
    ],
    "errors": [
        {"payload": "...", "error": "timeout"}
    ]
}
```

---

## 🔧 IMPLEMENTACIÓN DETALLADA

### 1. main.go

```go
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strings"
    "time"

    "go-xss-fuzzer/fuzzer"
    "go-xss-fuzzer/models"
)

func main() {
    // CLI Flags
    urlFlag := flag.String("u", "", "Target URL with FUZZ marker")
    payloadsFile := flag.String("p", "payloads/xss_payloads.txt", "Payloads file")
    concurrency := flag.Int("c", 50, "Number of concurrent requests")
    timeout := flag.Int("t", 10, "Request timeout in seconds")
    headers := flag.String("H", "", "Additional headers (comma-separated)")
    proxy := flag.String("proxy", "", "HTTP proxy URL")
    jsonOutput := flag.Bool("json", true, "Output as JSON")
    
    flag.Parse()
    
    if *urlFlag == "" {
        fmt.Fprintln(os.Stderr, "Error: -u (URL) is required")
        os.Exit(1)
    }
    
    // Parse headers
    headerMap := make(map[string]string)
    if *headers != "" {
        for _, h := range strings.Split(*headers, ",") {
            parts := strings.SplitN(h, ":", 2)
            if len(parts) == 2 {
                headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
            }
        }
    }
    
    // Load payloads
    payloads, err := fuzzer.LoadPayloads(*payloadsFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading payloads: %v\n", err)
        os.Exit(1)
    }
    
    // Create fuzzer config
    config := fuzzer.Config{
        URL:         *urlFlag,
        Payloads:    payloads,
        Concurrency: *concurrency,
        Timeout:     time.Duration(*timeout) * time.Second,
        Headers:     headerMap,
        ProxyURL:    *proxy,
    }
    
    // Run fuzzer
    result := fuzzer.Run(config)
    
    // Output
    if *jsonOutput {
        jsonBytes, _ := json.MarshalIndent(result, "", "  ")
        fmt.Println(string(jsonBytes))
    }
}
```

### 2. fuzzer/fuzzer.go

```go
package fuzzer

import (
    "crypto/tls"
    "io"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"

    "go-xss-fuzzer/models"
)

type Config struct {
    URL         string
    Payloads    []string
    Concurrency int
    Timeout     time.Duration
    Headers     map[string]string
    ProxyURL    string
}

func Run(config Config) *models.FuzzResult {
    startTime := time.Now()
    
    // Setup HTTP client
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        MaxIdleConns:    config.Concurrency,
        MaxConnsPerHost: config.Concurrency,
    }
    
    if config.ProxyURL != "" {
        proxyURL, _ := url.Parse(config.ProxyURL)
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    
    client := &http.Client{
        Transport: transport,
        Timeout:   config.Timeout,
    }
    
    // Result channels
    reflections := make(chan models.Reflection, len(config.Payloads))
    errors := make(chan models.FuzzError, len(config.Payloads))
    
    // Worker pool with semaphore
    sem := make(chan struct{}, config.Concurrency)
    var wg sync.WaitGroup
    
    for _, payload := range config.Payloads {
        wg.Add(1)
        go func(payload string) {
            defer wg.Done()
            
            sem <- struct{}{}        // Acquire
            defer func() { <-sem }() // Release
            
            result, err := testPayload(client, config, payload)
            if err != nil {
                errors <- models.FuzzError{Payload: payload, Error: err.Error()}
                return
            }
            
            if result.Reflected {
                reflections <- *result
            }
        }(payload)
    }
    
    // Wait for all goroutines
    go func() {
        wg.Wait()
        close(reflections)
        close(errors)
    }()
    
    // Collect results
    var resultReflections []models.Reflection
    var resultErrors []models.FuzzError
    
    for r := range reflections {
        resultReflections = append(resultReflections, r)
    }
    for e := range errors {
        resultErrors = append(resultErrors, e)
    }
    
    duration := time.Since(startTime)
    
    return &models.FuzzResult{
        Metadata: models.Metadata{
            Target:            config.URL,
            TotalPayloads:     len(config.Payloads),
            TotalRequests:     len(config.Payloads),
            DurationMs:        duration.Milliseconds(),
            RequestsPerSecond: float64(len(config.Payloads)) / duration.Seconds(),
        },
        Reflections: resultReflections,
        Errors:      resultErrors,
    }
}

func testPayload(client *http.Client, config Config, payload string) (*models.Reflection, error) {
    // Replace FUZZ marker with payload
    targetURL := strings.Replace(config.URL, "FUZZ", url.QueryEscape(payload), 1)
    
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return nil, err
    }
    
    // Add headers
    req.Header.Set("User-Agent", "BugTraceAI/1.0 XSS-Fuzzer")
    for k, v := range config.Headers {
        req.Header.Set(k, v)
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    bodyStr := string(body)
    
    // Check for reflection
    reflection := &models.Reflection{
        Payload:        payload,
        Reflected:      false,
        StatusCode:     resp.StatusCode,
        ResponseLength: len(body),
    }
    
    // Check unencoded reflection
    if strings.Contains(bodyStr, payload) {
        reflection.Reflected = true
        reflection.Encoded = false
        reflection.Context = detectContext(bodyStr, payload)
        return reflection, nil
    }
    
    // Check HTML-encoded reflection
    htmlEncoded := htmlEncode(payload)
    if strings.Contains(bodyStr, htmlEncoded) {
        reflection.Reflected = true
        reflection.Encoded = true
        reflection.EncodingType = "html_entities"
        reflection.Context = detectContext(bodyStr, htmlEncoded)
        return reflection, nil
    }
    
    return reflection, nil
}

func htmlEncode(s string) string {
    s = strings.ReplaceAll(s, "<", "&lt;")
    s = strings.ReplaceAll(s, ">", "&gt;")
    s = strings.ReplaceAll(s, "\"", "&quot;")
    return s
}

func detectContext(body, payload string) string {
    idx := strings.Index(body, payload)
    if idx == -1 {
        return "unknown"
    }
    
    // Simple context detection (can be improved)
    before := ""
    if idx > 50 {
        before = body[idx-50 : idx]
    } else {
        before = body[:idx]
    }
    
    if strings.Contains(before, "<script") {
        return "javascript"
    }
    if strings.HasSuffix(strings.TrimSpace(before), "=\"") || strings.HasSuffix(strings.TrimSpace(before), "='") {
        return "attribute_value"
    }
    if strings.HasSuffix(strings.TrimSpace(before), "=") {
        return "attribute_unquoted"
    }
    
    return "html_text"
}
```

### 3. models/result.go

```go
package models

type FuzzResult struct {
    Metadata    Metadata      `json:"metadata"`
    Reflections []Reflection  `json:"reflections"`
    Errors      []FuzzError   `json:"errors"`
}

type Metadata struct {
    Target            string  `json:"target"`
    Param             string  `json:"param,omitempty"`
    TotalPayloads     int     `json:"total_payloads"`
    TotalRequests     int     `json:"total_requests"`
    DurationMs        int64   `json:"duration_ms"`
    RequestsPerSecond float64 `json:"requests_per_second"`
}

type Reflection struct {
    Payload        string `json:"payload"`
    Reflected      bool   `json:"reflected"`
    Encoded        bool   `json:"encoded"`
    EncodingType   string `json:"encoding_type,omitempty"`
    Context        string `json:"context"`
    StatusCode     int    `json:"status_code"`
    ResponseLength int    `json:"response_length"`
}

type FuzzError struct {
    Payload string `json:"payload"`
    Error   string `json:"error"`
}
```

### 4. Makefile

```makefile
.PHONY: build test clean install

BINARY_NAME=go-xss-fuzzer
BUILD_DIR=../../bin

build:
 go build -o $(BUILD_DIR)/$(BINARY_NAME) .

build-linux:
 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux .

build-all: build-linux
 GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin .
 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME).exe .

test:
 go test -v ./...

clean:
 rm -f $(BUILD_DIR)/$(BINARY_NAME)*

install: build
 cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
```

---

## 🔗 INTEGRACIÓN CON PYTHON

### Modificar `bugtrace/tools/external.py`

```python
async def run_go_xss_fuzzer(url: str, param: str, payloads: List[str] = None) -> Dict:
    """
    Run the Go XSS fuzzer for high-performance payload testing.
    
    Returns:
        {
            "reflections": [...],
            "metadata": {...}
        }
    """
    binary_path = settings.TOOLS_DIR / "bin" / "go-xss-fuzzer"
    
    if not binary_path.exists():
        logger.warning("Go XSS fuzzer not found, falling back to Python")
        return None
    
    # Build URL with FUZZ marker
    fuzz_url = url.replace(f"{param}=", f"{param}=FUZZ")
    
    cmd = [
        str(binary_path),
        "-u", fuzz_url,
        "-c", "100",       # 100 concurrent goroutines
        "-t", "5",         # 5 second timeout
        "--json"
    ]
    
    if payloads:
        # Write payloads to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("\n".join(payloads))
            payloads_file = f.name
        cmd.extend(["-p", payloads_file])
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        
        if process.returncode == 0:
            return json.loads(stdout.decode())
        else:
            logger.error(f"Go XSS fuzzer failed: {stderr.decode()}")
            return None
    except Exception as e:
        logger.error(f"Go XSS fuzzer error: {e}")
        return None
```

### Modificar `bugtrace/agents/xss_agent.py`

```python
async def _fast_reflection_check(self, url: str, param: str, payloads: List[str]) -> List[str]:
    """
    Use Go fuzzer if available, otherwise fall back to Python.
    Returns list of reflected payloads.
    """
    # Try Go fuzzer first
    go_result = await external_tools.run_go_xss_fuzzer(url, param, payloads)
    
    if go_result and go_result.get("reflections"):
        logger.info(f"[{self.name}] Go fuzzer found {len(go_result['reflections'])} reflections in {go_result['metadata']['duration_ms']}ms")
        return [r["payload"] for r in go_result["reflections"] if not r["encoded"]]
    
    # Fallback to Python
    return await self._python_reflection_check(url, param, payloads)
```

---

## ✅ VERIFICACIÓN

### 1. Build and test locally

```bash
cd tools/go-xss-fuzzer
go mod init go-xss-fuzzer
go mod tidy
make build
./go-xss-fuzzer -u "https://httpbin.org/get?q=FUZZ" -c 10 -t 5
```

### 2. Benchmark against Python

```bash
# Python (current)
time python3 -c "
import asyncio
import aiohttp
payloads = ['<script>alert(1)</script>'] * 50
# ... test
"

# Go (new)
time ./go-xss-fuzzer -u 'https://target.com/search?q=FUZZ' -c 100
```

### 3. Integration test

```bash
./bugtraceai-cli http://127.0.0.1:5050 --clean
# Verify logs show "Go fuzzer found X reflections"
```

---

## ⛔ DO NOT DO

1. ❌ Don't rewrite the entire XSSAgent in Go (keep Python for LLM/orchestration)
2. ❌ Don't add Go as a project dependency (it's a standalone tool)
3. ❌ Don't require Go installation for users (ship pre-compiled binaries)

---

## 📁 FILES SUMMARY

| File | Action | Description |
|------|--------|-------------|
| `tools/go-xss-fuzzer/` | Create | New Go project directory |
| `tools/go-xss-fuzzer/main.go` | Create | CLI entry point |
| `tools/go-xss-fuzzer/fuzzer/fuzzer.go` | Create | Core fuzzing logic |
| `tools/go-xss-fuzzer/models/result.go` | Create | JSON output models |
| `tools/go-xss-fuzzer/Makefile` | Create | Build targets |
| `bugtrace/tools/external.py` | Modify | Add `run_go_xss_fuzzer` |
| `bugtrace/agents/xss_agent.py` | Modify | Integrate Go fuzzer |
| `bin/go-xss-fuzzer` | Create | Compiled binary |
