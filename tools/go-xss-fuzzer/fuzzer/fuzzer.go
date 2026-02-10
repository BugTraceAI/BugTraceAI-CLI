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

	// Check unencoded reflection (exact match)
	if strings.Contains(bodyStr, payload) {
		reflection.Reflected = true
		reflection.Encoded = false
		reflection.Context = detectContext(bodyStr, payload)
		return reflection, nil
	}

	// Check backslash-transform reflection (\ → \\)
	// Servers often escape backslashes: \';alert()// → \\';alert()//
	if strings.Contains(payload, "\\") {
		transformed := strings.ReplaceAll(payload, "\\", "\\\\")
		if strings.Contains(bodyStr, transformed) {
			reflection.Reflected = true
			reflection.Encoded = true
			reflection.EncodingType = "backslash_escape"
			reflection.Context = detectContext(bodyStr, transformed)
			return reflection, nil
		}
	}

	// Check executable-part reflection (breakout payloads)
	// For payloads like \';alert(document.domain)// the server may transform
	// the breakout prefix but the exec part (alert(document.domain)//) still reflects
	for _, breakout := range []string{"\\'", "\\\"", "';", "\";"} {
		if strings.Contains(payload, breakout) {
			parts := strings.SplitN(payload, breakout, 2)
			if len(parts) == 2 && len(parts[1]) > 5 {
				execPart := parts[1]
				if strings.Contains(bodyStr, execPart) {
					reflection.Reflected = true
					reflection.Encoded = true
					reflection.EncodingType = "partial_exec"
					reflection.Context = detectContext(bodyStr, execPart)
					return reflection, nil
				}
			}
		}
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

	// Look back up to 200 chars for better context detection
	lookback := 200
	start := idx - lookback
	if start < 0 {
		start = 0
	}
	before := body[start:idx]
	beforeLower := strings.ToLower(before)

	// Check if inside <script> block
	lastScriptOpen := strings.LastIndex(beforeLower, "<script")
	lastScriptClose := strings.LastIndex(beforeLower, "</script")
	inScript := lastScriptOpen != -1 && (lastScriptClose == -1 || lastScriptOpen > lastScriptClose)

	if inScript {
		// Refine: is it inside a JS string?
		trimmed := strings.TrimRight(before, " \t\n\r")
		if strings.HasSuffix(trimmed, "'") || strings.HasSuffix(trimmed, "= '") {
			return "js_string_single"
		}
		if strings.HasSuffix(trimmed, "\"") || strings.HasSuffix(trimmed, "= \"") {
			return "js_string_double"
		}
		return "script_tag"
	}

	// Check HTML attribute context
	trimmed := strings.TrimSpace(before)
	if strings.HasSuffix(trimmed, "=\"") || strings.HasSuffix(trimmed, "='") {
		return "attribute_value"
	}
	if strings.HasSuffix(trimmed, "=") {
		return "attribute_unquoted"
	}

	// Check if inside an HTML tag (between < and >)
	lastOpen := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")
	if lastOpen != -1 && (lastClose == -1 || lastOpen > lastClose) {
		return "html_tag"
	}

	return "html_text"
}
