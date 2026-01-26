package diff

import (
	"crypto/md5"
	"encoding/hex"
	"strings"

	"go-idor-fuzzer/models"
)

var SensitiveKeywords = []string{"email", "password", "ssn", "credit_card", "token", "address", "phone", "hash"}

func Compare(baseline models.Baseline, currentBody string, currentStatus int) (bool, string, []string) {
	// 1. Status Code Change
	if currentStatus != baseline.StatusCode {
		if currentStatus == 200 {
			return true, "status_code_change", DetectSensitive(currentBody)
		}
	}

	// 2. Response Length Change (±10%)
	length := len(currentBody)
	diff := float64(length) / float64(baseline.ResponseLength)
	if diff < 0.9 || diff > 1.1 {
		return true, "length_change", DetectSensitive(currentBody)
	}

	// 3. Hash Change
	currentHash := GetMD5Hash(currentBody)
	if currentHash != baseline.ResponseHash {
		// Even if length is similar, content changed
		return true, "hash_change", DetectSensitive(currentBody)
	}

	return false, "", nil
}

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func DetectSensitive(body string) []string {
	var found []string
	lowerBody := strings.ToLower(body)
	for _, kw := range SensitiveKeywords {
		if strings.Contains(lowerBody, kw) {
			found = append(found, kw)
		}
	}
	return found
}
