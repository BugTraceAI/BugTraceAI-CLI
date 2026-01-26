package fuzzer

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
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

func LoadPayloads(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}
	return payloads, scanner.Err()
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
		go func(p string) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			result, err := testPayload(client, config, p)
			if err != nil {
				errors <- models.FuzzError{Payload: p, Error: err.Error()}
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
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func detectContext(body, payload string) string {
	idx := strings.Index(body, payload)
	if idx == -1 {
		return "unknown"
	}

	// Simple context detection
	before := ""
	if idx > 50 {
		before = body[idx-50 : idx]
	} else {
		before = body[:idx]
	}

	beforeLower := strings.ToLower(before)

	if strings.Contains(beforeLower, "<script") {
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
