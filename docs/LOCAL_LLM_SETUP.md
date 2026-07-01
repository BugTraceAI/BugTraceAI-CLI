# Local LLM Setup Guide for BugTraceAI-CLI

This guide explains how to configure and run BugTraceAI-CLI using a local, self-hosted LLM (Qwen) via Podman or Docker instead of using cloud-based OpenRouter.

Running locally keeps all scan data on your network, requires no API keys, and has zero usage costs.

---

## 🚀 Recommended Setup: Ollama + Qwen

We recommend using **Ollama** as the local inference engine because it is lightweight, CPU-friendly, handles model loading automatically, and runs seamlessly in Podman or Docker.

### 1. Start Ollama in Podman (or Docker)

Use the provided compose configuration to start Ollama:

```bash
# Start Ollama service
podman-compose -f podman-compose.local-llm.yml up -d
```

*(If you use Docker instead of Podman, just replace `podman-compose` with `docker compose`)*

### 2. Pull the Qwen model

Once the container is running, pull the coding-optimized Qwen model (`qwen2.5-coder:7b`, ~4.7GB):

```bash
# Pull model using Podman
podman exec -it bugtrace_ollama ollama pull qwen2.5-coder:7b
```

---

## ⚙️ Configure BugTraceAI-CLI

To tell BugTrace to use your local Ollama setup:

1. Open `bugtraceaicli.conf`.
2. Under `[PROVIDER]`, set `ACTIVE = local-llm`.
3. In your `.env` file, uncomment the following line if you want to override the endpoint (defaults to `http://localhost:11434/v1/chat/completions`):
   ```ini
   LOCAL_LLM_BASE_URL=http://localhost:11434/v1/chat/completions
   ```

*(Note: No API key is required. BugTrace will bypass the validation checks for local-llm)*

---

## 🔬 Verifying Setup

Run the connectivity check to verify BugTrace can talk to Ollama:

```bash
python -c "from bugtrace.core.llm_client import llm_client; import asyncio; asyncio.run(llm_client.verify_connectivity())"
```

If successful, you will see a message:
`✓ Model qwen2.5-coder:7b is ONLINE.`

Now you can run your scans normally:
```bash
python -m bugtrace scan https://example.com
```

---

## ⚡ Alternative Inference Engines

Since BugTrace uses standard OpenAI-compatible API schemas for local LLMs, you can point to any local server by updating `LOCAL_LLM_BASE_URL` in `.env`:

### vLLM (Best performance for GPU)
```yaml
# Start vLLM service
# LOCAL_LLM_BASE_URL=http://localhost:8000/v1/chat/completions
```

### llama.cpp-server (Very lightweight C/C++ engine)
```yaml
# Start llama-cpp-server
# LOCAL_LLM_BASE_URL=http://localhost:8080/v1/chat/completions
```

---

## 🖥️ System Requirements & Sizing Guide

| Model Name | VRAM / RAM | Run On | Rationale |
|------------|------------|--------|-----------|
| **`qwen2.5-coder:7b`** | **~5 GB** | **CPU or GPU** | **Recommended default.** Lightweight and handles code generation / vulnerability analysis very well. |
| `qwen2.5-coder:14b` | ~9 GB | GPU | Better reasoning, requires dedicated GPU for good speeds. |
| `qwen2.5-coder:32b` | ~20 GB | High-end GPU | Best accuracy, but slow unless accelerated by GPU. |
