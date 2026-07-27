package diff

import (
	"regexp"
	"strings"

	"go-idor-fuzzer/models"
)

// SemanticAnalysis performs intelligent IDOR detection beyond simple hash comparison
type SemanticAnalysis struct {
	Baseline models.Baseline
	Current  ResponseData
}

type ResponseData struct {
	Body       string
	StatusCode int
	Length     int
	Hash       string
}

// Indicator represents a specific IDOR detection mechanism
type Indicator struct {
	Name        string
	Description string
	Severity    string
	Check       func(baseline models.Baseline, current ResponseData) bool
}

// IDORIndicators defines all IDOR detection mechanisms
var IDORIndicators = []Indicator{
	// 1. Permission Bypass
	{
		Name:        "permission_bypass",
		Description: "Status code changed from error to success",
		Severity:    "CRITICAL",
		Check: func(baseline models.Baseline, current ResponseData) bool {
			return (baseline.StatusCode == 401 || baseline.StatusCode == 403) &&
				current.StatusCode == 200
		},
	},

	// 2. User-Specific Data Patterns
	{
		Name:        "user_data_leakage",
		Description: "Response contains user-specific identifiers different from baseline",
		Severity:    "CRITICAL",
		Check: func(baseline models.Baseline, current ResponseData) bool {
			baselineUsers := extractUserIdentifiers(baseline.Body)
			currentUsers := extractUserIdentifiers(current.Body)
			return hasDifferentUserIDs(baselineUsers, currentUsers)
		},
	},

	// 3. Sensitive Data Exposure (Enhanced)
	{
		Name:        "sensitive_data_exposure",
		Description: "Response contains sensitive fields not in baseline",
		Severity:    "HIGH",
		Check: func(baseline models.Baseline, current ResponseData) bool {
			baselineSensitive := extractSensitiveFields(baseline.Body)
			currentSensitive := extractSensitiveFields(current.Body)
			return containsNewSensitiveData(baselineSensitive, currentSensitive)
		},
	},

	// 4. Structural Similarity (NOT an IDOR if structure is the same)
	{
		Name:        "structural_change",
		Description: "HTML/JSON structure changed significantly",
		Severity:    "LOW",
		Check: func(baseline models.Baseline, current ResponseData) bool {
			baselineStructure := extractStructure(baseline.Body)
			currentStructure := extractStructure(current.Body)
			similarity := calculateStructuralSimilarity(baselineStructure, currentStructure)

			// If structure is >90% similar, likely just content change (NOT IDOR)
			// If structure is <50% similar, might be accessing different resource type
			return similarity < 0.5
		},
	},
}

// extractUserIdentifiers finds user-specific patterns in response
func extractUserIdentifiers(body string) []string {
	var identifiers []string

	// Common user ID patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`"user_id":\s*"?(\d+)"?`),
		regexp.MustCompile(`"userId":\s*"?(\d+)"?`),
		regexp.MustCompile(`"email":\s*"([^"]+@[^"]+)"`),
		regexp.MustCompile(`"username":\s*"([^"]+)"`),
		regexp.MustCompile(`data-user-id="(\d+)"`),
		regexp.MustCompile(`/users/(\d+)`),
		regexp.MustCompile(`/profile/(\d+)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				identifiers = append(identifiers, match[1])
			}
		}
	}

	return identifiers
}

// extractSensitiveFields detects PII and sensitive data
func extractSensitiveFields(body string) map[string][]string {
	sensitive := make(map[string][]string)

	patterns := map[string]*regexp.Regexp{
		"email":         regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		"phone":         regexp.MustCompile(`\+?[\d\s\-\(\)]{10,}`),
		"ssn":           regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
		"credit_card":   regexp.MustCompile(`\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}`),
		"address":       regexp.MustCompile(`\d+\s+[\w\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)`),
		"api_key":       regexp.MustCompile(`(?:api[_-]?key|apikey|access[_-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})`),
		"password_hash": regexp.MustCompile(`["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']?(\$2[aby]\$\d+\$[./A-Za-z0-9]{53})`),
	}

	for fieldType, pattern := range patterns {
		matches := pattern.FindAllString(body, -1)
		if len(matches) > 0 {
			sensitive[fieldType] = matches
		}
	}

	return sensitive
}

// hasDifferentUserIDs checks if current response references different users
func hasDifferentUserIDs(baseline, current []string) bool {
	if len(baseline) == 0 || len(current) == 0 {
		return false
	}

	baselineSet := make(map[string]bool)
	for _, id := range baseline {
		baselineSet[id] = true
	}

	// If ANY user ID in current is NOT in baseline = potential IDOR
	for _, id := range current {
		if !baselineSet[id] {
			return true
		}
	}

	return false
}

// extractStructure analyzes HTML/JSON structure (not content)
func extractStructure(body string) map[string]int {
	structure := make(map[string]int)

	// HTML tags
	htmlTags := regexp.MustCompile(`<(\w+)[^>]*>`)
	matches := htmlTags.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			structure["tag:"+match[1]]++
		}
	}

	// JSON keys (if JSON response)
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		jsonKeys := regexp.MustCompile(`"(\w+)"\s*:`)
		matches := jsonKeys.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				structure["key:"+match[1]]++
			}
		}
	}

	return structure
}

// calculateStructuralSimilarity computes Jaccard similarity
func calculateStructuralSimilarity(baseline, current map[string]int) float64 {
	if len(baseline) == 0 && len(current) == 0 {
		return 1.0
	}

	intersection := 0
	union := 0

	all := make(map[string]bool)
	for k := range baseline {
		all[k] = true
	}
	for k := range current {
		all[k] = true
	}

	for k := range all {
		baseCount := baseline[k]
		currCount := current[k]

		if baseCount > 0 && currCount > 0 {
			intersection++
		}
		union++
	}

	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

// containsNewSensitiveData checks if new PII appeared
func containsNewSensitiveData(baseline, current map[string][]string) bool {
	for fieldType, currentValues := range current {
		baselineValues, exists := baseline[fieldType]

		// New type of sensitive data appeared
		if !exists && len(currentValues) > 0 {
			return true
		}

		// More instances of sensitive data
		if len(currentValues) > len(baselineValues) {
			return true
		}
	}

	return false
}

// AnalyzeIDOR performs comprehensive IDOR analysis
func AnalyzeIDOR(baseline models.Baseline, current ResponseData) (bool, string, []string, []string) {
	var triggeredIndicators []string
	maxSeverity := "LOW"

	// Run all IDOR indicators
	for _, indicator := range IDORIndicators {
		if indicator.Check(baseline, current) {
			triggeredIndicators = append(triggeredIndicators, indicator.Name)

			// Track highest severity
			if indicator.Severity == "CRITICAL" {
				maxSeverity = "CRITICAL"
			} else if indicator.Severity == "HIGH" && maxSeverity != "CRITICAL" {
				maxSeverity = "HIGH"
			}
		}
	}

	// Only report IDOR if HIGH or CRITICAL indicators triggered
	if len(triggeredIndicators) > 0 && (maxSeverity == "HIGH" || maxSeverity == "CRITICAL") {
		sensitive := extractSensitiveFields(current.Body)
		sensitiveKeys := make([]string, 0, len(sensitive))
		for k := range sensitive {
			sensitiveKeys = append(sensitiveKeys, k)
		}

		return true, strings.Join(triggeredIndicators, ","), sensitiveKeys, nil
	}

	// Check structural similarity for rejection
	structureSimilarity := calculateStructuralSimilarity(
		extractStructure(baseline.Body),
		extractStructure(current.Body),
	)

	// If structure is >90% similar, it's just content change (e.g., different product)
	if structureSimilarity > 0.9 {
		return false, "high_structural_similarity", nil, []string{"Different content, same structure (e.g., product catalog)"}
	}

	return false, "", nil, nil
}
