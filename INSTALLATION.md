# 🚀 Installation Guide — BugTraceAI-CLI

## Quick Start with Installation Wizard

The easiest way to get BugTraceAI-CLI up and running is using the interactive installation wizard:

```bash
./install.sh
```

The wizard provides two installation modes:
- **Local Installation**: Python virtual environment setup (best for development)
- **Docker Installation**: Containerized deployment with automatic port detection (best for production)

## 📋 Prerequisites

### For Local Installation
- ✅ Python 3.10 or higher
- ✅ pip3 (Python package manager)
- ✅ Docker (required for some agents: GoSpider, Nuclei, SQLMap)
- ⚙️ nmap (optional, but recommended)
- ⚙️ Git (for cloning the repository)

### For Docker Installation
- ✅ Docker Engine
- ✅ Docker Compose (or `docker compose` plugin)
- ✅ Git (for cloning the repository)

### Both Modes Require
- 🔑 OpenRouter API key ([get one here](https://openrouter.ai/keys))

## 🐍 Local Installation (Development Mode)

### What the Wizard Does

When you choose **Option 1: Local Installation**, the wizard will:

1. ✅ Check if Python 3, pip, Docker, and nmap are installed
2. 📄 Create `.env` file from `.env.example` (if not exists)
3. 🐍 Create a Python virtual environment in `.venv/`
4. 📦 Install all Python dependencies from `requirements.txt`
5. 🌐 Install Playwright Chromium browser
6. 🔧 Build Go fuzzers (XSS, SSRF, IDOR, LFI)
7. 📁 Create necessary directories (`reports/`, `logs/`, `data/`)

### After Installation

```bash
# Activate the virtual environment
source .venv/bin/activate

# Configure your API key in .env
nano .env  # Add your OPENROUTER_API_KEY

# Run a scan
./bugtraceai-cli scan https://example.com

# Run an authenticated scan (login-protected target)
./bugtraceai-cli scan https://example.com --auth-config auth_config.yaml

# Or start the API server
./bugtraceai-cli serve --port 8000

# Evaluate model performance
./bugtraceai-cli model_eval --provider openrouter-v2
```

### Pros & Cons

**✅ Advantages:**
- Full access to source code for customization
- Faster iteration during development
- No Docker image rebuild needed for code changes
- Direct access to logs and debugging

**⚠️ Disadvantages:**
- Requires Python 3.10+ installed on your system
- Must manage dependencies manually
- System-level dependencies (nmap, Docker) required

## 🐳 Docker Installation (Production Mode)

### What the Wizard Does

When you choose **Option 2: Docker Installation**, the wizard will:

1. ✅ Check if Docker and Docker Compose are installed
2. ✅ Verify Docker daemon is running
3. 📄 Create `.env` file from `.env.example` (if not exists)
4. 🔍 **Automatically detect if port 8000 is in use**
5. 🎯 **Find the next available port** if 8000 is occupied
6. ⚙️ Update `docker-compose.yml` with the selected port
7. 🏗️ Build the Docker image (includes Go fuzzers, Playwright, PyTorch)
8. 🚀 Start the container in detached mode
9. ⏳ Wait for the API to be ready (health check)

### Automatic Port Detection Example

```bash
$ ./install.sh
...
⚙️ Configuring network ports...
⚠ Default port 8000 is already in use
⚙️ Searching for available port starting from 8000...
→ Found available port: 8003
Use port 8003? [Y/n]: y

→ Using port: 8003
⚙️ Updating docker-compose.yml with port 8003...
✓ Port configuration updated
```

### After Installation

The API will be running at the selected port:

```bash
# Check API health
curl http://localhost:8000/health
# Or if port was changed: http://localhost:8003/health

# View API documentation
open http://localhost:8000/docs

# View container logs
docker compose logs -f

# Stop the container
docker compose stop

# Start the container
docker compose start

# Restart the container
docker compose restart

# Stop and remove the container
docker compose down
```

### Using the API

```bash
# Trigger a scan via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get scan status
curl http://localhost:8000/api/scans/{scan_id}

# List all scans
curl http://localhost:8000/api/scans

# Trigger an authenticated scan via API
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "auth_config_path": "/app/auth_config.yaml"}'
```

### Pros & Cons

**✅ Advantages:**
- Isolated environment (no conflicts with system packages)
- Consistent behavior across different machines
- Easy deployment to production servers
- All dependencies bundled (Go fuzzers, Playwright, PyTorch)
- Automatic port conflict resolution

**⚠️ Disadvantages:**
- Longer initial build time (5-10 minutes)
- Must rebuild image after code changes
- Requires Docker knowledge for troubleshooting

## 🔧 Configuration

### Environment Variables

Edit `.env` to configure BugTraceAI-CLI:

```bash
# Required: Your OpenRouter API key
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxx

# Optional: CORS origins for Web UI
BUGTRACE_CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Optional: Override LLM models
# DEFAULT_MODEL=google/gemini-2.0-flash-thinking-exp:free
# SKEPTICAL_MODEL=anthropic/claude-3.5-haiku:beta
# VISION_MODEL=google/gemini-2.0-flash-thinking-exp:free
```

### Authenticated Scanning (YAML + TOTP/2FA)

BugTraceAI-CLI supports scanning **login-protected applications** via a YAML configuration file. This includes support for TOTP (Time-Based One-Time Password) token generation for 2FA-protected targets.

**Create `auth_config.yaml`:**

```yaml
login_url: https://target.com/login
username: pentester@example.com
password: your_password_here
totp_secret: BASE32TOTPSECRETHERE   # optional — for 2FA/TOTP apps
success_condition: "dashboard"      # string that confirms successful login
```

**Run an authenticated scan:**

```bash
./bugtraceai-cli scan https://target.com --auth-config auth_config.yaml
```

The scanner will automatically:
1. Navigate to `login_url`
2. Fill in credentials
3. Generate a real-time TOTP token (if `totp_secret` is set)
4. Confirm login success via `success_condition`
5. Reuse the authenticated session across all 6 scan phases

> The `auth_config.yaml` is automatically included in the report ZIP for audit traceability.

### Port Configuration (Docker Only)

The wizard automatically handles port conflicts, but you can manually edit `docker-compose.yml`:

```yaml
services:
  api:
    ports:
      - "8000:8000"  # Change left number to use different host port
```

## 🐛 Troubleshooting

### Local Installation Issues

**Problem: Python version too old**
```bash
python3 --version  # Must be 3.10 or higher
```
Solution: Install Python 3.10+ or use Docker installation instead.

**Problem: Virtual environment activation fails**
```bash
source .venv/bin/activate
# If using fish shell:
source .venv/bin/activate.fish
```

**Problem: Playwright installation fails**
```bash
# Manually install Playwright
playwright install chromium
playwright install-deps chromium
```

### Docker Installation Issues

**Problem: Docker daemon not running**
```bash
sudo systemctl start docker
# Or on macOS:
open -a Docker
```

**Problem: Permission denied when running Docker commands**
```bash
# Add your user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

**Problem: Port already in use**
The wizard automatically detects this, but you can manually:
```bash
# Find what's using port 8000
sudo lsof -i :8000
# Or
sudo netstat -tulpn | grep 8000
```

**Problem: Build fails due to network issues**
```bash
# Retry with clean build
docker compose build --no-cache
```

**Problem: Container exits immediately**
```bash
# Check logs for errors
docker compose logs
```

### API Key Issues

**Problem: API returns authentication errors**
- Verify your OpenRouter API key is correct in `.env`
- Ensure `.env` file exists and is not named `.env.txt`
- For Docker: Restart container after changing `.env`

```bash
# Verify .env is loaded (Local)
cat .env

# Verify .env is loaded (Docker)
docker compose config
```

## 📊 Verifying Installation

### Local Installation

```bash
# Activate virtual environment
source .venv/bin/activate

# Check Python packages
pip list | grep -E "playwright|fastapi|typer"

# Check Go fuzzers
ls -la tools/bin/

# Test CLI
./bugtraceai-cli --help

# Quick health check
python3 -c "import playwright; print('✓ Playwright OK')"
```

### Docker Installation

```bash
# Check container is running
docker compose ps

# Check API health
curl http://localhost:8000/health

# Expected response:
# {"status": "healthy", "version": "3.5.7-beta"}

# Check logs
docker compose logs --tail=50

# Access container shell
docker compose exec api bash
```

## 🔄 Switching Between Modes

You can run the wizard multiple times to switch installation modes:

```bash
# Already have local installation? Add Docker too:
./install.sh
# Choose option 2

# Want to switch from Docker to local development?
docker compose down  # Stop Docker
./install.sh
# Choose option 1
```

Both modes can coexist on the same system.

## 🚀 Next Steps

After installation, see the [README.md](README.md) for:
- Running your first scan
- Configuration options
- Agent documentation
- Output formats
- Advanced usage

## 🆘 Need Help?

| Resource | Link |
|---|---|
| 📖 **Wiki** | [deepwiki.com/BugTraceAI/BugTraceAI-CLI](https://deepwiki.com/BugTraceAI/BugTraceAI-CLI) |
| 🌐 **Website** | [bugtraceai.com](https://bugtraceai.com) |
| 🐛 **Issues** | [GitHub Issues](https://github.com/BugTraceAI/BugTraceAI-CLI/issues) |
| 💬 **Contact** | [@yz9yt](https://x.com/yz9yt) |

---

Made with ❤️ by the BugTraceAI team
