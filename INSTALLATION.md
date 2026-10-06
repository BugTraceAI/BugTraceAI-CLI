# BugTraceAI-CLI 4.0 — Installation and terminal workspace

## Install

The [universal Launcher](https://github.com/BugTraceAI/BugTraceAI-Launcher)
(3.3.14+) provides the platform installation menu and connects the selected
components. Choose Terminal for TUI, WEB for the browser workspace, or a
server profile for integrations. Install through the visual menu:

```bash
curl -fsSL https://raw.githubusercontent.com/BugTraceAI/BugTraceAI-Launcher/main/install.sh | bash
```

In a CLI checkout, bare `./install.sh` opens that same menu with `terminal`
suggested. The Launcher is the only guided installer. Direct installation in
this checkout uses an explicit runtime backend, with no second menu:

```bash
git clone https://github.com/BugTraceAI/BugTraceAI-CLI.git
cd BugTraceAI-CLI
./scripts/install-runtime.sh --interface tui --runtime local --global yes
```

Choose the required interface and execution method in the command:

| Option | Meaning |
| --- | --- |
| `--interface tui` | Terminal workspace only; no API services |
| `--interface api` | Web-scanning API/MCP for WEB, agents and integrations |
| `--interface both` | Terminal workspace plus web-scanning API/MCP |
| `--runtime local` | Python environment and scanner dependencies on this machine |
| `--runtime docker` | Scanner dependencies inside containers; TUI still opens in your terminal |
| `--global yes` | Register the current-user `btai` command on Linux/macOS |
| `--launch yes` | Open the TUI when installation finishes; requires a terminal |

`--interface` and `--runtime` are required for a fresh direct installation.
`--global` and `--launch` default to `no`. Missing options fail before installing
anything. A direct install does not include the WEB application. Local
installation requires Python 3.10+; Docker installation requires Docker Engine
and Compose. Some scanner tools also use Docker during local scans.

TUI adds Textual. API adds FastAPI, Uvicorn, WebSockets and MCP. Local packages
are installed from the selected extras in `pyproject.toml`. The installer
prepares the environment, Chromium and scanner tools for the selected runtime.
On Linux, the local installer selects the CPU build of PyTorch before installing
the engine, avoiding unnecessary CUDA packages. It checks that a virtual
environment can create its own working pip, including on fresh Ubuntu systems.
On Linux it automatically installs missing `pip`/`venv` packages and `nmap`
through the system package manager, asking for `sudo` only when needed. On
macOS it uses Homebrew when available. Docker is reported as optional for a
local TUI profile; choose the Docker runtime when Docker should be required.

The Docker profile prepares the runtime before building the selected CLI
interfaces. On Linux it installs missing Docker Engine using the official
Docker installer, starts the daemon and installs Compose if needed. On macOS
it starts an existing Docker Desktop installation or uses Homebrew to install
Docker, Compose and Colima. Homebrew must already be available for that setup.
Administrator/password prompts remain in your terminal. Existing working
Docker installations are reused. If a Linux socket needs administrator access,
the installer and `btai` use `sudo` for Docker commands without changing groups.
Unavailable custom Docker contexts are reported rather than switched.
Docker builds select the Nuclei binary for x86_64 or ARM64; the latter includes
Apple Silicon Docker runtimes.

For scripted installations:

```bash
./scripts/install-runtime.sh --interface tui --runtime local --global yes
./scripts/install-runtime.sh --interface api --runtime docker --global no
./scripts/install-runtime.sh --interface both --runtime docker --global yes
./scripts/install-runtime.sh --reuse
```

For compatibility, explicit `./install.sh --interface ... --runtime ...`
options, `./install.sh --reuse` and `--standalone [options]` still delegate to
the same backend. `--standalone` alone does not open a component wizard.
System privilege/password prompts remain in your terminal when required.

Installation choices are remembered in `.bugtrace-install.env` without API
keys. Reuse updates or repairs the saved profile. Existing environments retain
previously installed packages when switching interfaces.

## Install with your AI coding agent

Copy this prompt into an agent with terminal access, such as Claude Code,
Cursor or Codex. The default installs this CLI checkout directly as a local
TUI and registers a global `btai` command on Linux/macOS. For the connected
platform, use the universal Launcher profile instead.

```text
Install BugTraceAI-CLI directly from this checkout as a standalone terminal
workspace. Use the local Python runtime and register the current-user btai
command. Perform the installation; do not start a scan.

Read README.md and INSTALLATION.md first. Preserve existing configuration,
credentials and uncommitted changes. Do not replace this checkout or switch
its repository or branch silently.

For a fresh install, review the documented CLI options, then run:
./scripts/install-runtime.sh --interface tui --runtime local --global yes

If I ask for Docker or API/MCP, use the corresponding CLI installer options.
If I ask for the connected WEB platform, use the BugTraceAI Launcher `web`
profile; `full` adds this terminal TUI. Universal profiles require Launcher
3.3.14 or newer.

Resolve setup errors using the repository
instructions. Keep system privilege/password prompts in my local terminal.
Never ask me to paste credentials into chat or print existing secrets. I will
configure an LLM provider locally through Provider/F7. Auth/F8 configures
target login separately.

Verify the version, saved profile and installed components. For TUI, verify
startup and quit in an interactive terminal when available; otherwise state
that visual verification is pending. Check btai registration and PATH in a
fresh shell. For servers, check health and MCP on the actual configured
ports. Do not start a scan as part of installation.

Finish with the installation directory, selected profile, checks performed
and exact commands to open the installed interfaces.
```

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
Z.ai. Uncheck Save this key in local .env to keep a newly entered key only in the
current session. Provider selection lasts until the TUI closes.

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
`./scripts/install-runtime.sh --reuse --global-only --global yes`.

If `btai` is not found in the terminal used for installation, open a new
terminal or activate the command directory in that same shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
btai
```

You can also start immediately with `~/.local/bin/btai`. The installer cannot
change the PATH of the shell that launched it. Registering the command needs
no sudo; a Docker installation may still ask for sudo when starting the TUI.

After a successful interactive TUI/both installation, the wizard offers to
open the real TUI immediately. Press Enter to accept or `n` to finish. It uses
the checkout path, so the new command directory need not be in the current
terminal's PATH. Opening the workspace does not start a scan. Quitting returns
to the installer; a launch failure keeps the completed installation/profile.

Use `--launch no` to skip that final prompt. `--launch yes` opens directly
after installation and requires a terminal. Noninteractive runs and
`--global-only` do not prompt to launch; API-only installations do not offer
the TUI.

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

## Updates and compatible versions

For Launcher-managed installations, use Launcher 3.3.14+ and review
`./launcher.sh update --plan` before `./launcher.sh update`. The visual menu also
has **Update installation**. Source tags come from one compatible release
manifest; preparation finishes before activation, and saved settings/data remain
in place. Use `./launcher.sh update --recover` for an interrupted activation.

See the [release and recovery guide](https://github.com/BugTraceAI/BugTraceAI-Launcher/blob/main/RELEASES.md).
Direct component checkouts keep their explicit runtime backend. Choose tagged
versions deliberately, retain local configuration and data, and rerun that
backend; a development checkout is not silently moved to a public release.
