# BugTraceAI-CLI — Agent Instructions

## Git Remotes & Push Policy

- `dev` → `BugTraceAI-CLI-DEV` (private) — all development pushes go here
- `origin` → `BugTraceAI-CLI` (public) — clean releases only, NEVER push directly
- The public repo was recreated on 2026-02-16 with a clean single-commit history
- **NEVER push to origin** — only push to `dev`

## Public Repo Exclusions (CRITICAL)

The public repo (`origin`) does NOT contain and MUST NOT contain:

- **`tests/`** — All test files are internal only, excluded from public repo
- **Hardcoded secrets or credentials** — All secrets must be in env vars or `.env`
- **`BUGTRACE_ANTHROPIC_CLIENT_ID`** — Must come from environment variable, NEVER hardcode the OAuth Client ID

## Commit Rules

- NO `Co-Authored-By` lines in commits
- Stage specific files, never use `git add .` or `git add -A`
- Push to `dev` remote only

## Key Architecture

- FastAPI backend on port 8000
- SQLite database (`bugtrace.db`) is source of truth for all scan data
- Config: `bugtraceaicli.conf` (no hardcoded values, externalize to config/env)
