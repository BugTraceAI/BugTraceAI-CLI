# ============================================================
# Stage 1: Go Builder - Compile Go fuzzers (XSS, SSRF, IDOR, LFI)
# ============================================================
FROM golang:1.24-alpine AS go-builder

RUN apk add --no-cache bash

WORKDIR /build/tools

# Copy all Go fuzzer source directories
COPY tools/go-xss-fuzzer/ go-xss-fuzzer/
COPY tools/go-ssrf-fuzzer/ go-ssrf-fuzzer/
COPY tools/go-idor-fuzzer/ go-idor-fuzzer/
COPY tools/go-lfi-fuzzer/ go-lfi-fuzzer/
COPY tools/build_fuzzers.sh build_fuzzers.sh

RUN chmod +x build_fuzzers.sh && bash build_fuzzers.sh

# ============================================================
# Stage 2: Docker CLI - Get static binary from official image
# ============================================================
FROM docker:cli AS docker-cli

# ============================================================
# Stage 3: Runtime - Python + Playwright + Docker CLI
# ============================================================
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Docker CLI binary from official image (avoids broken docker.io on slim)
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

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

# Playwright Chromium (headless browser for DOM XSS testing)
RUN playwright install chromium && playwright install-deps chromium

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
