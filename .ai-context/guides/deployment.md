# BugTraceAI CLI - Deployment Guide

## Quick Start

Start the API server with the built-in CLI command:

```bash
bugtraceai-cli serve
```

The server starts at **http://127.0.0.1:8000** by default.

Verify the server is running:

```bash
# Health check - returns server status, docker availability, active scans
curl http://localhost:8000/health

# Readiness check
curl http://localhost:8000/ready
```

## Production Uvicorn Configuration

For production deployments, run uvicorn directly with tuned settings:

```bash
uvicorn bugtrace.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Recommended Production Flags

| Flag | Value | Purpose |
|------|-------|---------|
| `--host` | `0.0.0.0` | Bind to all interfaces |
| `--port` | `8000` | Listen port |
| `--workers` | `4` | Number of worker processes (2x CPU cores typical) |
| `--log-level` | `warning` | Reduce log verbosity in production |
| `--access-log` | (enabled by default) | HTTP request logging |
| `--ssl-keyfile` | `key.pem` | TLS private key for HTTPS |
| `--ssl-certfile` | `cert.pem` | TLS certificate for HTTPS |

### Full Production Command

```bash
uvicorn bugtrace.api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --log-level warning \
  --ssl-keyfile /etc/ssl/private/key.pem \
  --ssl-certfile /etc/ssl/certs/cert.pem
```

## Docker Setup

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the CLI package
RUN pip install --no-cache-dir -e .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "bugtrace.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--log-level", "warning"]
```

### docker-compose.yml

```yaml
version: "3.8"

services:
  bugtrace-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - BUGTRACE_ENV=production
      - BUGTRACE_CORS_ORIGINS=https://yourdomain.com
    volumes:
      - bugtrace-data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  bugtrace-data:
```

### Running with Docker

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f bugtrace-api

# Stop
docker compose down
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUGTRACE_ENV` | `development` | Environment mode. Set to `production` for production deployments. |
| `BUGTRACE_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated list of allowed CORS origins. |

### Example

```bash
export BUGTRACE_ENV=production
export BUGTRACE_CORS_ORIGINS=https://app.example.com,https://admin.example.com
```

## API Documentation

When the server is running, interactive API documentation is available:

| Endpoint | Description |
|----------|-------------|
| [http://localhost:8000/docs](http://localhost:8000/docs) | Swagger UI - interactive API explorer |
| [http://localhost:8000/redoc](http://localhost:8000/redoc) | ReDoc - clean API reference |
| [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json) | OpenAPI 3.0 JSON schema |
