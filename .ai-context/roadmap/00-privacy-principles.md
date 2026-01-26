# Privacy-First Principles - BugTraceAI-CLI

## Core Philosophy

**BugTraceAI-CLI is designed for bug bounty hunters and security researchers who CANNOT leak target information.**

All features MUST respect these principles:

---

## 🔒 Privacy Rules

### Rule #1: Local-First by Default
- **All data stays on user's machine** (or their VPC)
- No cloud services for observability, telemetry, or analytics
- No "phone home" features
- No automatic update checks (manual only)

### Rule #2: External API Transparency
- Only external API: **OpenRouter** (LLM inference)
- User explicitly provides API key
- Prompts are sanitized before sending (remove credentials, emails, etc.)
- LLM audit logs stored locally only

### Rule #3: Zero Telemetry
```python
# ❌ NEVER do this
send_usage_stats_to_server(scan_results)

# ✅ ALWAYS do this
save_locally("~/.bugtrace/logs/scan.jsonl", scan_results)
```

### Rule #4: Opt-In Only Features
Any feature that could leak data MUST:
- Be **disabled by default**
- Require explicit user consent
- Show clear warnings about data sharing
- Provide anonymization options

---

## 🖥️ Infrastructure Requirements

### Target Environment
**Typical Bug Hunter Setup:**
- Ubuntu 22.04/24.04 Desktop or Server
- 8GB RAM minimum (16GB recommended)
- 20GB disk space
- Optional: VPC with GUI (XFCE/LXDE for browser automation)

### Resource Budget (8GB VPC)
```
Component                RAM Usage
─────────────────────────────────
Ubuntu + XFCE           ~1.0 GB
BugTraceAI-CLI          ~1.5 GB
Neo4j (Docker)          ~2.0 GB
Prometheus (local)      ~0.5 GB
Grafana (local)         ~0.3 GB
Playwright Browser      ~1.0 GB
LanceDB (disk-based)    ~0.2 GB
System buffers          ~1.5 GB
─────────────────────────────────
TOTAL                   ~8.0 GB ✅
```

---

## ✅ Approved Technologies (Local)

### Databases
- ✅ **SQLite**: Local file-based DB
- ✅ **LanceDB**: Local vector DB (`.lance` files)
- ✅ **Neo4j**: Docker container, localhost only

### Observability
- ✅ **Prometheus**: Localhost metrics (`localhost:9090`)
- ✅ **Grafana**: Localhost dashboards (`localhost:3000`)
- ✅ **JSONL logs**: Local files in `~/.bugtrace/logs/`

### Browser Automation
- ✅ **Playwright**: Local browser instances
- ✅ **Chrome DevTools Protocol (CDP)**: Localhost only

### LLM Inference
- ✅ **OpenRouter API**: User provides key, prompts sanitized
- ⚠️ **Future**: Local LLM support (Ollama, vLLM) for 100% offline

---

## ❌ Banned Technologies

### Cloud Services (Privacy Violations)
- ❌ **Langfuse Cloud**: Sends traces to external server
- ❌ **Sentry**: Error reporting to cloud
- ❌ **Mixpanel/Amplitude**: Analytics services
- ❌ **PostHog**: Product analytics
- ❌ **DataDog/New Relic**: Cloud monitoring

### Community Features (Must Be Opt-In)
- ⚠️ **Federated Learning**: Only with explicit consent + anonymization
- ⚠️ **Scan Sharing**: Optional export, user manually shares
- ⚠️ **Plugin Marketplace**: Local catalog, no phone home

---

## 🔧 Configuration Template

```ini
# ~/.bugtrace/config.conf

[PRIVACY]
LOCAL_ONLY=true                      # Everything local by default
TELEMETRY_ENABLED=false              # No usage stats
CRASH_REPORTS=false                  # No error reporting to cloud
AUTO_UPDATE_CHECK=false              # Manual updates only

[OBSERVABILITY]
PROMETHEUS_ENABLED=true              # Local metrics
PROMETHEUS_PORT=9090
GRAFANA_ENABLED=true                 # Local dashboards
GRAFANA_PORT=3000
LOG_DIRECTORY=~/.bugtrace/logs       # Local logs only

[KNOWLEDGE_GRAPH]
NEO4J_URI=bolt://localhost:7687      # Local Neo4j
NEO4J_USER=neo4j
NEO4J_PASSWORD=<user-provided>
LANCEDB_PATH=~/.bugtrace/lancedb     # Local vector DB

[LLM]
OPENROUTER_API_KEY=<user-provided>   # Only external API
SANITIZE_PROMPTS=true                # Remove sensitive data before API call
AUDIT_LOG_PATH=~/.bugtrace/logs/llm_audit.jsonl

[COMMUNITY]  # All disabled by default
SHARE_ANONYMOUS_STATS=false          # Opt-in only
FEDERATED_LEARNING=false             # Opt-in only
PLUGIN_MARKETPLACE_URL=local         # No external server
```

---

## 🚀 Docker Compose (Local Stack)

```yaml
# docker-compose.yml - All services localhost only
version: '3.8'

services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "127.0.0.1:7474:7474"  # Browser (localhost only)
      - "127.0.0.1:7687:7687"  # Bolt (localhost only)
    environment:
      NEO4J_AUTH: neo4j/bugtrace123
      NEO4J_dbms_memory_heap_max__size: 2G
    volumes:
      - ~/.bugtrace/neo4j:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "127.0.0.1:9090:9090"  # Localhost only
    volumes:
      - ~/.bugtrace/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ~/.bugtrace/prometheus/data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.listen-address=127.0.0.1:9090'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "127.0.0.1:3000:3000"  # Localhost only
    environment:
      GF_SECURITY_ADMIN_PASSWORD: bugtrace123
      GF_USERS_ALLOW_SIGN_UP: false
    volumes:
      - ~/.bugtrace/grafana:/var/lib/grafana
    restart: unless-stopped
```

---

## 🔐 Data Flow Diagram

```
┌─────────────────────────────────────────────────────┐
│           Bug Hunter's Machine / VPC                │
│                                                     │
│  ┌──────────────┐    ┌─────────────────┐          │
│  │ BugTraceAI   │───▶│ SQLite (local)  │          │
│  │    CLI       │    └─────────────────┘          │
│  └──────┬───────┘                                  │
│         │                                           │
│         ├──────▶ LanceDB (local .lance files)      │
│         │                                           │
│         ├──────▶ Neo4j (localhost:7687)            │
│         │                                           │
│         ├──────▶ Prometheus (localhost:9090)       │
│         │                                           │
│         └──────▶ Logs (~/.bugtrace/logs/*.jsonl)   │
│                                                     │
└─────────────────────────────────────────────────────┘
                        │
                        │ ONLY EXTERNAL CONNECTION
                        ▼
                  ┌──────────────┐
                  │  OpenRouter  │ (Sanitized LLM prompts)
                  │     API      │
                  └──────────────┘
```

---

## 📊 Roadmap Impact

### Phase 2 Adjustments
- ✅ **Observability**: Prometheus + Grafana (local) instead of Langfuse
- ✅ **Knowledge Graph**: Neo4j local, NO federated learning
- ✅ **CI/CD**: GitHub Actions OK (user controls their CI)

### Phase 4 Deferred (Future)
- ⚠️ **Community Sharing**: Marked as opt-in, future feature
- ⚠️ **Plugin Marketplace**: Local catalog first, cloud optional

---

## 🎯 Success Criteria

A feature is **privacy-compliant** if:
1. ✅ Runs 100% on user's machine/VPC
2. ✅ No data leaves machine without explicit user action
3. ✅ Works offline (except LLM inference)
4. ✅ Fits in 8GB RAM budget
5. ✅ Can run in air-gapped environment (with pre-downloaded models)

---

## 🔮 Future: 100% Offline Mode

**Phase 5 (Optional):**
- Integrate **Ollama** or **vLLM** for local LLM inference
- Download models once: `llama3.1-8b`, `qwen2.5-coder-7b`
- Zero external API calls
- Ideal for air-gapped pentesting labs

```bash
# Future command
bugtraceai-cli scan --mode offline --local-llm ollama:llama3.1 https://target.com
```

---

## Summary

**BugTraceAI-CLI is built for security professionals who value privacy.**

- 🔒 All data local by default
- 🖥️ Runs on 8GB VPC or Ubuntu desktop
- 🚫 No telemetry, no cloud dependencies
- ✅ Only external API: OpenRouter (with sanitization)
- 🔮 Future: 100% offline mode with local LLMs
