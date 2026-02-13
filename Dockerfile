# ============================================================
# Stage 1: Go Builder - Compile Go fuzzers (XSS, SSRF, IDOR, LFI)
#           + Build GoSpider from source (native, no Docker-in-Docker)
# ============================================================
FROM golang:1.24-alpine AS go-builder

RUN apk add --no-cache bash git

WORKDIR /build/tools

# Copy all Go fuzzer source directories
COPY tools/go-xss-fuzzer/ go-xss-fuzzer/
COPY tools/go-ssrf-fuzzer/ go-ssrf-fuzzer/
COPY tools/go-idor-fuzzer/ go-idor-fuzzer/
COPY tools/go-lfi-fuzzer/ go-lfi-fuzzer/
COPY tools/build_fuzzers.sh build_fuzzers.sh

RUN chmod +x build_fuzzers.sh && bash build_fuzzers.sh

# Build GoSpider natively (eliminates trickest/gospider Docker image at runtime)
ENV CGO_ENABLED=0
RUN go install github.com/jaeles-project/gospider@latest && \
    cp $(go env GOPATH)/bin/gospider /build/tools/bin/gospider

# ============================================================
# Stage 2: Download Nuclei pre-built binary
# ============================================================
FROM alpine:3.19 AS nuclei-downloader

ARG NUCLEI_VERSION=3.3.7

RUN apk add --no-cache curl unzip && \
    curl -sL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# ============================================================
# Stage 3: Docker CLI - Static binary (fallback for future tools)
# ============================================================
FROM docker:cli AS docker-cli

# ============================================================
# Stage 4: Runtime - Python + Playwright + Native Tools + Docker CLI
# ============================================================
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Docker CLI binary (fallback when native tools unavailable)
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# Native security tools (preferred over Docker-in-Docker execution)
COPY --from=nuclei-downloader /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /build/tools/bin/gospider /usr/local/bin/gospider

# System dependencies:
#   gcc   - build some Python C extensions
#   nmap  - network scanning
#   curl  - health checks + utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies (includes PyTorch CPU, sentence_transformers, FastAPI, etc.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# SQLMap - native Python SQL injection tool (replaces googlesky/sqlmap Docker image)
RUN pip install --no-cache-dir sqlmap

# Playwright Chromium (headless browser for DOM XSS testing)
RUN playwright install chromium && playwright install-deps chromium

# Download Nuclei vulnerability templates at build time
RUN nuclei -update-templates 2>/dev/null || true

# Copy Go fuzzer binaries from builder stage
COPY --from=go-builder /build/tools/bin/ /app/tools/bin/

# Copy project source code
COPY . .

# Create directories for persistent data
RUN mkdir -p /app/reports /app/logs /app/data

# Entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
