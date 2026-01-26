# Developer Experience - Feature Tasks

## Feature Overview
Improve onboarding and UX with setup wizard, configuration profiles, progress indicators, and auto-update.

**Phase**: 4 - Polish & Ecosystem
**Duration**: 2 weeks
**Effort**: $15k

---

## 🟣 Setup Wizard

### FEATURE-083: Interactive Setup Command
**Complexity**: 🔵 MEDIUM (3 days)

```python
# bugtraceai-cli init
def interactive_setup():
    print("Welcome to BugTraceAI-CLI Setup!")
    print("[1/5] API Keys Configuration")

    api_key = input("Enter OpenRouter API Key: ")
    glm_key = input("Enter GLM API Key (optional): ")

    print("[2/5] Model Selection")
    print("1) Gemini 3 Flash (recommended)")
    print("2) Qwen 2.5 Coder")
    print("3) DeepSeek Chat")
    model_choice = input("Choose primary model (1-3): ")

    # Save to .env
    with open(".env", "w") as f:
        f.write(f"OPENROUTER_API_KEY={api_key}\n")
        f.write(f"GLM_API_KEY={glm_key}\n")
        f.write(f"DEFAULT_MODEL={model_map[model_choice]}\n")

    print("✅ Setup complete!")
```

---

## 🟣 Configuration Profiles

### FEATURE-084: Add Scan Profiles
**Complexity**: 🟣 QUICK (2 days)

```bash
# Quick scan (5 minutes)
./bugtraceai-cli scan --profile quick https://target.com

# Thorough scan (1 hour)
./bugtraceai-cli scan --profile thorough https://target.com

# Bug bounty scan (2 hours, all features)
./bugtraceai-cli scan --profile bug-bounty https://target.com
```

---

## 🔵 Progress Indicators

### FEATURE-085: Add Rich Progress Bars
**Complexity**: 🔵 MEDIUM (3 days)

```python
# pip install rich
from rich.progress import Progress, SpinnerColumn, TextColumn

with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    transient=True,
) as progress:
    task1 = progress.add_task("[cyan]Crawling URLs...", total=100)
    task2 = progress.add_task("[green]Testing vulnerabilities...", total=31)

    # Update progress
    progress.update(task1, advance=1)
```

### FEATURE-086: Real-Time Agent Status
**Complexity**: 🔵 MEDIUM (2 days)

```
Scan Progress: 45% [=========>        ]

Active Agents (5/31):
  ✓ XSS Agent: Testing parameter 'search' [2.3s]
  ⏳ SQLi Agent: Running SQLMap [45.1s]
  ✓ IDOR Agent: Analyzing access controls [12.8s]
  ⚠ JWT Agent: Invalid token format
  ⏳ SSRF Agent: Testing localhost bypass [8.4s]

Findings: 3 HIGH, 7 MEDIUM, 12 LOW
Cost: $0.45 (estimated)
ETA: 8 minutes remaining
```

### FEATURE-087: Cost Tracking Display
**Complexity**: 🟣 QUICK (1 day)

```
💰 Cost Tracker:
  Total spent: $2.34
  By model: Gemini ($1.50), Qwen ($0.84)
  Estimated final: $4.20
```

---

## 🔵 Auto-Update

### FEATURE-088: Check for Updates
**Complexity**: 🔵 MEDIUM (2 days)

```python
async def check_for_updates():
    response = await httpx.get("https://api.github.com/repos/bugtrace/bugtrace-cli/releases/latest")
    latest = response.json()["tag_name"]

    if latest > settings.VERSION:
        print(f"New version available: {latest}")
        print("Run: bugtraceai-cli update")
```

### FEATURE-089: Auto-Install Updates
**Complexity**: 🔵 MEDIUM (2 days)

```bash
$ bugtraceai-cli update
Checking for updates... v2.1.0 available!
Downloading... [=========>  ] 89%
Installing... Done!
Restart required.
```

---

## Summary

**Total Tasks**: 7 (Phase 4a - DX)
**Estimated Effort**: 2 weeks
**Investment**: ~$15k
