# Custom and Local LLM Provider Presets

BugTraceAI-CLI includes presets for OpenRouter, Z.ai, and Anthropic. You can
also add a preset for an API you operate or have credentials for when it
implements the OpenAI Chat Completions request and response format. This is a
useful option for the OpenAI API, OpenAI-compatible providers, and local model
servers such as Ollama.

This guide configures the LLM used by the scanner. It does **not** configure an
MCP client: Codex, Claude Code, Cursor, and other assistants connect separately
to the MCP endpoint after the CLI is running. A ChatGPT/Codex subscription OAuth
login is also different from an OpenAI API key and is not enabled by a preset.

## 1. Create a preset

Create `bugtrace/data/providers/my-provider.json`, replacing the endpoint,
environment-variable name, and model ID with values from your provider.

```json
{
  "id": "my-provider",
  "name": "My OpenAI-compatible provider",
  "recommended": false,
  "api_format": "openai",
  "base_url": "https://api.example.com/v1/chat/completions",
  "api_key_env": "MY_PROVIDER_API_KEY",
  "api_key_hint": "provider API key",
  "failover": [],
  "features": {
    "description": "Custom OpenAI-compatible provider.",
    "online_mode": false,
    "balance_check": false,
    "model_discovery": false
  },
  "models": {
    "DEFAULT_MODEL": "my-model",
    "CODE_MODEL": "my-model",
    "ANALYSIS_MODEL": "my-model",
    "ANALYSIS_PENTESTER_MODEL": "my-model",
    "ANALYSIS_BUG_BOUNTY_MODEL": "my-model",
    "ANALYSIS_AUDITOR_MODEL": "my-model",
    "ANALYSIS_RED_TEAM_MODEL": "my-model",
    "ANALYSIS_RESEARCHER_MODEL": "my-model",
    "PRIMARY_MODELS": "my-model",
    "VISION_MODEL": "my-model",
    "VALIDATION_VISION_MODEL": "my-model",
    "WAF_DETECTION_MODELS": "my-model",
    "MUTATION_MODEL": "my-model",
    "SKEPTICAL_MODEL": "my-model",
    "REPORTING_MODEL": "my-model",
    "LONEWOLF_MODEL": "my-model"
  },
  "pricing": {
    "my-model": { "input": 0.0, "output": 0.0 }
  }
}
```

`base_url` must be the complete chat-completions endpoint, not just the server
origin. Keep every model slot in the preset on models that the selected provider
actually serves. If the model does not accept images, disable vision validation
in `bugtraceaicli.conf`:

```ini
[VALIDATION]
VISION_ENABLED = False
```

## 2. Select the preset and provide its key

Set the provider ID in `bugtraceaicli.conf`:

```ini
[PROVIDER]
ACTIVE = my-provider
```

Add the matching API key to `.env`; never commit this file:

```dotenv
MY_PROVIDER_API_KEY=replace-with-your-key
```

For a local server that does not validate credentials, the pre-flight check
still requires a value longer than 10 characters. Use a harmless local-only
placeholder where the server permits it.

## 3. Apply the change

For a local Python installation, restart the CLI after saving the preset and
configuration. For Docker, the preset is built into the image, so rebuild and
restart the services:

```bash
docker compose up -d --build
```

When a Docker container must reach a model server running on the host, use an
address reachable from inside the container. Docker Desktop normally provides
`host.docker.internal`; on plain Linux, configure Docker's `host-gateway`
mapping before using that hostname.

## Troubleshooting

- **Provider preset not found:** the JSON filename must match `[PROVIDER] ACTIVE`
  exactly, and Docker must be rebuilt after adding it.
- **Model not found or unsupported:** replace every model slot in the preset
  with valid IDs from that provider, then restart.
- **Authentication failure:** verify that `api_key_env` and the variable in
  `.env` use the same name.
- **Not OpenAI-compatible:** this template cannot translate a provider-specific
  protocol. Use a compatible gateway or add a dedicated integration first.
