package models

type LFIResult struct {
	Metadata Metadata   `json:"metadata"`
	Hits     []LFIHit   `json:"hits"`
	Errors   []LFIError `json:"errors"`
}

type Metadata struct {
	Target            string  `json:"target"`
	OSDetected        string  `json:"os_detected"`
	TotalPayloads     int     `json:"total_payloads"`
	DurationMs        int64   `json:"duration_ms"`
	RequestsPerSecond float64 `json:"requests_per_second"`
}

type LFIHit struct {
	Payload   string `json:"payload"`
	FileFound string `json:"file_found"`
	Evidence  string `json:"evidence"`
	Encoding  string `json:"encoding"`
	Severity  string `json:"severity"`
}

type LFIError struct {
	Payload string `json:"payload"`
	Error   string `json:"error"`
}
