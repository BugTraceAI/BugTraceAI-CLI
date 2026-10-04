# BugTraceAI-CLI 4.0 — Installation and terminal workspace

## Install

```bash
git clone https://github.com/BugTraceAI/BugTraceAI-CLI.git
cd BugTraceAI-CLI
./install.sh
```

The wizard asks for **TUI**, **API + MCP**, or **both**, followed by **local
Python** or **Docker**. It then offers a user-global **btai** command on Linux
and macOS. Local installation requires Python 3.10+; Docker installation
requires Docker Engine and Compose. Some scanner tools also use Docker during
local scans. The scanning engine and browser dependencies are shared.

TUI adds Textual. API adds FastAPI, Uvicorn, WebSockets and MCP. Local packages
are installed from the selected extras in `pyproject.toml`. The installer
prepares the environment, Chromium and scanner tools for the selected runtime.

For scripted installations:

```bash
./install.sh --interface tui --runtime local --global yes
./install.sh --interface api --runtime docker --global no
./install.sh --interface both --runtime docker --global yes
./install.sh --reuse
```

Installation choices are remembered in `.bugtrace-install.env` without API
keys. Reuse updates or repairs the saved profile. Existing environments retain
previously installed packages when switching interfaces.

## Open the real TUI

```bash
./bugtraceai-cli
# If the global command was selected, open a new terminal:
btai
```

Enter your target URL at the top, set **Depth** (1–10) and **Max URLs**
(1–5000), configure **Provider** with F7 and press **Start**. Opening the
workspace does not require an API key; real scans require the selected provider
key. Provider uses the engine's presets, including OpenRouter, Anthropic and
Z.ai. Entered keys remain in the session unless you select Save in local .env.
Provider selection lasts until the TUI closes.

The TUI runs the full pipeline: **Recon → Discovery → Strategy → Exploit →
Validate → Report**. Its five tabs show distinct information:

| Tab | Shortcut | Contents |
| --- | --- | --- |
| Pipeline | F2 | Stages, counters and elapsed times |
| Findings | F3 | Searchable vulnerability evidence |
| Agents | F4 | Specialist states, queues and runtime |
| Timeline | F5 | Milestones and alerts |
| Logs | F6 | Searchable engine output |

F1 opens help. Ctrl+S starts, Ctrl+X stops, Ctrl+E exports all captured findings
and Ctrl+Q quits. Pause takes effect at the next pipeline checkpoint. URLs
belong in the top form; the lower bar accepts slash commands such as `/help`,
`/provider`, `/auth`, `/pause`, `/resume`, `/stop` and `/export`.

An explicit preview is available without scanning:

```bash
./bugtraceai-cli tui --demo
```

## Target authentication

Use **Auth**, F8 or `/auth` to configure the website's credentials separately
from the LLM provider key. Choose a masked **Bearer token** or load a **login
YAML** using the same format as the WEB. Apply validates the YAML and loads a
session snapshot; reapply to reload later file edits. Target credentials are
not saved by the TUI. Authentication can be changed before or after a scan.
Switching methods replaces supplied Authorization/Cookie headers and login
settings while preserving unrelated custom headers. None removes the supplied
authentication; combined CLI authentication can also be kept unchanged.

Example `auth-config.yaml`:

```yaml
authentication:
  login_url: "/login"
  login_type: form
  credentials:
    username: "user@example.com"
    password: "your-password"
    # totp_secret: "YOUR_BASE32_SECRET"
  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"
    # - "Enter $totp in the code field"
  success_condition:
    type: url_contains
    value: "/dashboard"
```

TOTP/2FA is optional. Replace the example values with the target's login flow
and a valid Base32 TOTP secret when required. Relative login URLs are resolved
against the scan target. In Docker, use a YAML path accessible inside the
scanner container.

## Docker TUI

For a TUI-only installation:

```bash
docker compose -f docker-compose.tui.yml run --rm scanner
```

This profile opens an interactive scanner without starting API/MCP servers or
publishing ports. With both interfaces installed:

```bash
docker compose exec api python3 -m bugtrace tui
```

The global `btai` helper opens the saved local or Docker TUI profile. Keep the
registered checkout at its installation path. Global registration uses
`~/.local/bin` and configures Bash/Zsh PATH without sudo; an unrelated existing
`btai` command is preserved. Registration can be retried with
`./install.sh --global-only --global yes`.

## API and MCP

For a local API installation:

```bash
./bugtraceai-cli serve --port 8000
```

API documentation is available at `/docs`; health is available at `/health`.
MCP is a separate command: `./bugtraceai-cli mcp --help` lists its transport and
port options. For Docker API/both installations, use `docker compose up -d`.
The installer stores the selected API port in `.env`; changing that port must
keep the listener, published port and health check aligned. API/MCP mode can be
used by BugTraceAI-WEB without opening the TUI.

## Command use

The launcher activates the installed local environment automatically.
Explicit commands such as `scan`, `audit` and focused agents retain text
output for scripts; redirected output remains ordinary text. To open a full
interactive scan directly:

```bash
./bugtraceai-cli full https://target.example
./bugtraceai-cli --help
```
