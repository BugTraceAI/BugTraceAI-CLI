package models

type FuzzResult struct {
	Metadata    Metadata      `json:"metadata"`
	Reflections []Reflection  `json:"reflections"`
	Errors      []FuzzError   `json:"errors"`
}

type Metadata struct {
	Target            string  `json:"target"`
	Param             string  `json:"param,omitempty"`
	TotalPayloads     int     `json:"total_payloads"`
	TotalRequests     int     `json:"total_requests"`
	DurationMs        int64   `json:"duration_ms"`
	RequestsPerSecond float64 `json:"requests_per_second"`
}

type Reflection struct {
	Payload        string `json:"payload"`
	Reflected      bool   `json:"reflected"`
	Encoded        bool   `json:"encoded"`
	EncodingType   string `json:"encoding_type,omitempty"`
	Context        string `json:"context"`
	StatusCode     int    `json:"status_code"`
	ResponseLength int    `json:"response_length"`
}

type FuzzError struct {
	Payload string `json:"payload"`
	Error   string `json:"error"`
}
