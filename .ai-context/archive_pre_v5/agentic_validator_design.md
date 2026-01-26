# Agentic Validator Design Document

## Overview

The **AgenticValidator** is an AI-powered vulnerability validation agent that uses vision LLMs to intelligently analyze screenshots and validate security findings. This is inspired by Claude's "Computer Use" / "Browser Subagent" pattern.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     AgenticValidator                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. EXECUTE PAYLOAD                                              │
│     ├─ Construct exploitation URL                                │
│     ├─ Navigate with Playwright                                  │
│     └─ Capture screenshot                                        │
│                                                                  │
│  2. BASIC VALIDATION (fast path)                                 │
│     ├─ Check for alert() trigger                                 │
│     ├─ Check for SQL error patterns                              │
│     └─ If triggered → VALIDATED ✓                                │
│                                                                  │
│  3. VISION VALIDATION (fallback)                                 │
│     ├─ Encode screenshot as base64                               │
│     ├─ Send to Vision LLM (Gemini Flash)                         │
│     ├─ Parse AI reasoning                                        │
│     └─ If confident → VALIDATED ✓                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. Vision-Based XSS Detection

Instead of just checking if `alert()` was called, the AI can:

- See if XSS proof banner is visible
- Detect if payload is reflected as HTML vs escaped text
- Recognize WAF blocks vs actual exploitation

### 2. SQL Injection Analysis

The AI can identify:

- MySQL/PostgreSQL/MSSQL error messages
- Database version disclosures
- Unexpected data in responses

### 3. Adaptive Reasoning

Unlike static checks, the AI can:

- Understand context of what it sees
- Provide confidence scores
- Suggest next steps for unclear cases

---

## Usage

### Direct Usage

```python
from bugtrace.agents.agentic_validator import agentic_validator

# Validate a single finding
finding = await agentic_validator.validate_finding_agentically(finding)

# Validate batch
findings = await agentic_validator.validate_batch(findings)
```

### In Orchestrator

```python
# Enable agentic validation in config
settings.USE_AGENTIC_VALIDATOR = True

# The orchestrator will automatically use it
```

---

## Prompts

### XSS Validation Prompt

The AI is given context about:

- What XSS is
- What payloads were injected
- What SUCCESS looks like (red banner, alert dialog)
- What FAILURE looks like (escaped text, WAF block)

### SQLi Validation Prompt

The AI looks for:

- SQL syntax error messages
- Database type identification
- Information disclosure

---

## Comparison: Basic vs Agentic

| Feature | Basic ValidatorAgent | AgenticValidator |
|---------|---------------------|------------------|
| XSS Check | `alert()` hook | Vision + `alert()` |
| SQLi Check | Pattern matching | Vision + Pattern |
| Confidence | Boolean | 0.0-1.0 score |
| Reasoning | None | Detailed explanation |
| Adaptability | Fixed rules | Context-aware |
| Cost | Free | LLM API cost |

---

## Cost Considerations

Each vision validation call uses the LLM API:

- ~1000 tokens per validation
- With Gemini Flash at $0.10/1M tokens = ~$0.0001 per validation
- For 40 findings = ~$0.004 additional

This is negligible compared to the value of accurate validation.

---

## Future Enhancements

1. **Multi-Step Validation**: Have the AI navigate, click, and interact
2. **Payload Generation**: Let AI suggest better payloads based on context
3. **DOM Analysis**: Feed DOM structure alongside screenshot
4. **Session Replay**: Save full browser session for review
5. **MCP Integration**: Use standardized Model Context Protocol for browser tools

---

## Files

- `/bugtrace/agents/agentic_validator.py` - Main implementation
- `/bugtrace/agents/validator.py` - Original basic validator (still available)

---

**Created**: 2026-01-07
**Author**: BugTraceAI Team
