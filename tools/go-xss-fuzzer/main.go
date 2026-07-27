package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go-xss-fuzzer/fuzzer"
)

func main() {
	// CLI Flags
	urlFlag := flag.String("u", "", "Target URL with FUZZ marker")
	payloadsFile := flag.String("p", "payloads/xss_payloads.txt", "Payloads file")
	concurrency := flag.Int("c", 50, "Number of concurrent requests")
	timeout := flag.Int("t", 10, "Request timeout in seconds")
	headers := flag.String("H", "", "Additional headers (comma-separated, e.g. 'Cookie: session=abc,User-Agent: test')")
	proxy := flag.String("proxy", "", "HTTP proxy URL")
	jsonOutput := flag.Bool("json", true, "Output as JSON")

	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: -u (URL) is required. Example: -u 'http://site.com/?q=FUZZ'")
		os.Exit(1)
	}

	// Parse headers
	headerMap := make(map[string]string)
	if *headers != "" {
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Load payloads
	payloads, err := fuzzer.LoadPayloads(*payloadsFile)
	if err != nil {
		// If file not found, try to use a minimal default set to avoid total failure
		fmt.Fprintf(os.Stderr, "Warning: Could not load payloads from %s: %v. Using defaults.\n", *payloadsFile, err)
		payloads = []string{
			"<script>alert(1)</script>",
			"\"><script>alert(1)</script>",
			" <img src=x onerror=alert(1)>",
		}
	}

	// Create fuzzer config
	config := fuzzer.Config{
		URL:         *urlFlag,
		Payloads:    payloads,
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeout) * time.Second,
		Headers:     headerMap,
		ProxyURL:    *proxy,
	}

	// Run fuzzer
	result := fuzzer.Run(config)

	// Output
	if *jsonOutput {
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonBytes))
	} else {
		fmt.Printf("Scan complete. Found %d reflections.\n", len(result.Reflections))
		for _, r := range result.Reflections {
			fmt.Printf("[+] Reflected: %s (Context: %s, Encoded: %v)\n", r.Payload, r.Context, r.Encoded)
		}
	}
}
