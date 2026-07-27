package models

type SSRFResult struct {
	Metadata     Metadata      `json:"metadata"`
	Hits         []SSRFHit     `json:"hits"`
	OOBCallbacks []OOBCallback `json:"oob_callbacks"`
	Errors       []SSRFError   `json:"errors"`
}

type Metadata struct {
	Target            string  `json:"target"`
	TotalPayloads     int     `json:"total_payloads"`
	DurationMs        int64   `json:"duration_ms"`
	RequestsPerSecond float64 `json:"requests_per_second"`
}

type SSRFHit struct {
	Payload          string `json:"payload"`
	ResponseContains string `json:"response_contains,omitempty"`
	StatusCode       int    `json:"status_code"`
	ResponseLength   int    `json:"response_length"`
	Severity         string `json:"severity"`
	Reason           string `json:"reason"`
}

type OOBCallback struct {
	Payload  string `json:"payload"`
	Received bool   `json:"received"`
}

type SSRFError struct {
	Payload string `json:"payload"`
	Error   string `json:"error"`
}
