package models

type IDORResult struct {
	Metadata Metadata    `json:"metadata"`
	Baseline Baseline    `json:"baseline"`
	Hits     []IDORHit   `json:"hits"`
	Errors   []IDORError `json:"errors"`
}

type Metadata struct {
	Target            string  `json:"target"`
	Range             string  `json:"range"`
	ValidIDsFound     int     `json:"valid_ids_found"`
	DurationMs        int64   `json:"duration_ms"`
	RequestsPerSecond float64 `json:"requests_per_second"`
}

type Baseline struct {
	ID             string `json:"id"`
	StatusCode     int    `json:"status_code"`
	ResponseLength int    `json:"response_length"`
	ResponseHash   string `json:"response_hash"`
	Body           string `json:"body,omitempty"` // For semantic analysis
}

type IDORHit struct {
	ID                string   `json:"id"`
	StatusCode        int      `json:"status_code"`
	ResponseLength    int      `json:"response_length"`
	IsDifferent       bool     `json:"is_different"`
	DiffType          string   `json:"diff_type"`
	ContainsSensitive []string `json:"contains_sensitive,omitempty"`
	Severity          string   `json:"severity"`
}

type IDORError struct {
	ID         string `json:"id"`
	StatusCode int    `json:"status_code"`
	Reason     string `json:"reason"`
}
