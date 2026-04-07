package fuzzer

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go-lfi-fuzzer/models"
)

type Config struct {
	URL         string
	Payloads    []string
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	ProxyURL    string
}

var Signatures = map[string]string{
	"root:x:0:0":      "linux",
	"bin:x:1:1":       "linux",
	"[fonts]":         "windows",
	"[extensions]":    "windows",
	"[boot loader]":   "windows",
	"cmndline":        "linux",
	"HTTP_USER_AGENT": "linux",
	"PATH=":           "both",
	"default_home":    "linux",
}

func Run(config Config) *models.LFIResult {
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
	}

	hitsChan := make(chan models.LFIHit, len(config.Payloads))
	errorsChan := make(chan models.LFIError, len(config.Payloads))

	sem := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	for _, payload := range config.Payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			hit, err := testPayload(client, config, p)
			if err != nil {
				errorsChan <- models.LFIError{Payload: p, Error: err.Error()}
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

	var hits []models.LFIHit
	var errors []models.LFIError
	osDetected := "unknown"

	for h := range hitsChan {
		hits = append(hits, h)
		if h.Severity == "CRITICAL" && osDetected == "unknown" {
			// Infer OS from hit (crude but useful)
			if strings.Contains(h.Payload, "etc/passwd") {
				osDetected = "linux"
			} else if strings.Contains(h.Payload, "win.ini") {
				osDetected = "windows"
			}
		}
	}
	for e := range errorsChan {
		errors = append(errors, e)
	}

	duration := time.Since(startTime)

	return &models.LFIResult{
		Metadata: models.Metadata{
			Target:            config.URL,
			OSDetected:        osDetected,
			TotalPayloads:     len(config.Payloads),
			DurationMs:        duration.Milliseconds(),
			RequestsPerSecond: float64(len(config.Payloads)) / duration.Seconds(),
		},
		Hits:   hits,
		Errors: errors,
	}
}

func testPayload(client *http.Client, config Config, payload string) (*models.LFIHit, error) {
	// 1. Prepare Target URL
	fuzzURL := strings.Replace(config.URL, "FUZZ", url.QueryEscape(payload), 1)

	req, err := http.NewRequest("GET", fuzzURL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	// 2. Execute Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// 3. Analyze Response
	for sig, _ := range Signatures {
		if strings.Contains(bodyStr, sig) {
			evidence := bodyStr
			if len(evidence) > 200 {
				idx := strings.Index(bodyStr, sig)
				start := idx - 50
				if start < 0 {
					start = 0
				}
				end := idx + 150
				if end > len(bodyStr) {
					end = len(bodyStr)
				}
				evidence = bodyStr[start:end]
			}

			return &models.LFIHit{
				Payload:   payload,
				FileFound: detectFilename(payload),
				Evidence:  strings.TrimSpace(evidence),
				Encoding:  detectEncoding(payload),
				Severity:  "CRITICAL",
			}, nil
		}
	}

	// 4. Secondary check: Error differential (Placeholder)
	// Some LFIs don't return content but change error messages from "not found" to "access denied"
	// This would require baseline logic.

	return nil, nil
}

func detectFilename(payload string) string {
	parts := strings.Split(payload, "/")
	return parts[len(parts)-1]
}

func detectEncoding(payload string) string {
	if strings.Contains(payload, "%2f") {
		return "url_encoded"
	}
	if strings.Contains(payload, "..%252f") {
		return "double_url_encoded"
	}
	if strings.Contains(payload, "....//") {
		return "filter_bypass"
	}
	return "none"
}
