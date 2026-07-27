package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go-idor-fuzzer/fuzzer"
)

func main() {
	urlFlag := flag.String("u", "", "Target URL with FUZZ marker")
	idRange := flag.String("range", "1-100", "Numeric ID range (e.g. 1-1000)")
	baselineID := flag.String("baseline", "1", "Baseline ID for comparison")
	concurrency := flag.Int("c", 100, "Concurrency")
	timeout := flag.Int("t", 5, "Timeout in seconds")
	headers := flag.String("H", "", "Headers (k:v,k:v)")
	jsonOutput := flag.Bool("json", true, "Output as JSON")

	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: -u (URL) is required")
		os.Exit(1)
	}

	// 1. Generate IDs from range
	var ids []string
	parts := strings.Split(*idRange, "-")
	if len(parts) == 2 {
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		for i := start; i <= end; i++ {
			ids = append(ids, strconv.Itoa(i))
		}
	} else {
		ids = strings.Split(*idRange, ",")
	}

	// 2. Parse Headers
	headerMap := make(map[string]string)
	if *headers != "" {
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	config := fuzzer.Config{
		URL:         *urlFlag,
		IDs:         ids,
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeout) * time.Second,
		Headers:     headerMap,
		BaselineID:  *baselineID,
	}

	result := fuzzer.Run(config)

	if *jsonOutput {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("IDOR Scan complete. Hits: %d\n", len(result.Hits))
		for _, h := range result.Hits {
			fmt.Printf("[%s] ID %s -> %s (Len: %d, Sensitive: %v)\n",
				h.Severity, h.ID, h.DiffType, h.ResponseLength, h.ContainsSensitive)
		}
	}
}
