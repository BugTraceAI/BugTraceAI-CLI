package fuzzer

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go-idor-fuzzer/diff"
	"go-idor-fuzzer/models"
)

type Config struct {
	URL         string
	IDs         []string
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	ProxyURL    string
	BaselineID  string
}

func Run(config Config) *models.IDORResult {
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

	// 1. Establish Baseline
	baseline := getBaseline(client, config)

	// 2. Run Fuzzer
	hitsChan := make(chan models.IDORHit, len(config.IDs))
	errorsChan := make(chan models.IDORError, len(config.IDs))

	sem := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	for _, id := range config.IDs {
		if id == config.BaselineID {
			continue
		}

		wg.Add(1)
		go func(id string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			hit, errHit := testID(client, config, id, baseline)
			if errHit != nil {
				errorsChan <- *errHit
				return
			}

			if hit != nil {
				hitsChan <- *hit
			}
		}(id)
	}

	go func() {
		wg.Wait()
		close(hitsChan)
		close(errorsChan)
	}()

	var hits []models.IDORHit
	var errors []models.IDORError

	for h := range hitsChan {
		hits = append(hits, h)
	}
	for e := range errorsChan {
		errors = append(errors, e)
	}

	duration := time.Since(startTime)

	return &models.IDORResult{
		Metadata: models.Metadata{
			Target:            config.URL,
			ValidIDsFound:     len(hits),
			DurationMs:        duration.Milliseconds(),
			RequestsPerSecond: float64(len(config.IDs)) / duration.Seconds(),
		},
		Baseline: baseline,
		Hits:     hits,
		Errors:   errors,
	}
}

func getBaseline(client *http.Client, config Config) models.Baseline {
	fuzzURL := strings.Replace(config.URL, "FUZZ", url.QueryEscape(config.BaselineID), 1)
	req, _ := http.NewRequest("GET", fuzzURL, nil)
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return models.Baseline{ID: config.BaselineID, StatusCode: 0}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	return models.Baseline{
		ID:             config.BaselineID,
		StatusCode:     resp.StatusCode,
		ResponseLength: len(body),
		ResponseHash:   diff.GetMD5Hash(bodyStr),
		Body:           bodyStr, // Store body for semantic analysis
	}
}

func testID(client *http.Client, config Config, id string, baseline models.Baseline) (*models.IDORHit, *models.IDORError) {
	fuzzURL := strings.Replace(config.URL, "FUZZ", url.QueryEscape(id), 1)
	req, err := http.NewRequest("GET", fuzzURL, nil)
	if err != nil {
		return nil, &models.IDORError{ID: id, StatusCode: 0, Reason: err.Error()}
	}

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, &models.IDORError{ID: id, StatusCode: 0, Reason: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Skip error responses (unless it's a permission bypass)
	if resp.StatusCode >= 400 && resp.StatusCode != baseline.StatusCode {
		return nil, &models.IDORError{ID: id, StatusCode: resp.StatusCode, Reason: "Status code indicates error"}
	}

	// ===== NEW: Semantic IDOR Analysis =====
	current := diff.ResponseData{
		Body:       bodyStr,
		StatusCode: resp.StatusCode,
		Length:     len(body),
		Hash:       diff.GetMD5Hash(bodyStr),
	}

	// Perform comprehensive semantic analysis
	isIDOR, indicators, sensitiveKeys, rejectionReasons := diff.AnalyzeIDOR(baseline, current)

	if isIDOR {
		// Determine severity based on indicators
		severity := "MEDIUM"
		if strings.Contains(indicators, "permission_bypass") || strings.Contains(indicators, "user_data_leakage") {
			severity = "CRITICAL"
		} else if strings.Contains(indicators, "sensitive_data_exposure") {
			severity = "HIGH"
		}

		return &models.IDORHit{
			ID:                id,
			StatusCode:        resp.StatusCode,
			ResponseLength:    len(body),
			IsDifferent:       true,
			DiffType:          indicators,
			ContainsSensitive: sensitiveKeys,
			Severity:          severity,
		}, nil
	}

	// Log rejection reason if available (for debugging)
	if len(rejectionReasons) > 0 {
		// Not an IDOR - likely just different content (e.g., product catalog)
		return nil, nil
	}

	return nil, nil
}
