# Agent Prompt Externalization & Refactoring

## 🚀 Overview

As of v1.7.2, BugTraceAI-CLI has transitioned from hardcoded system prompts to a **Fully Externalized Prompt Architecture**. All agent instructions, personas, and configurations now reside in dedicated Markdown files within `bugtrace/agents/system_prompts/`.

This refactor decouples the core agent logic (Python) from the behavioral instructions (Markdown), enabling rapid iteration and optimization of LLM interactions.

---

## 🏗️ Architecture

### 1. The `BaseAgent` Model

All agents now inherit from `bugtrace.agents.base.BaseAgent`. The base class automatically handles:

- Loading system prompts from `bugtrace/agents/system_prompts/{agent_id}.md`.
- Parsing YAML frontmatter for agent-specific configurations (`agent_config`).
- Fallback mechanisms to hardcoded prompts if external files are missing.

### 2. Prompt Management (Conductor V2)

The `ConductorV2` class (`bugtrace/core/conductor.py`) serves as the central hub for:

- Providing shared context and security rules.
- Validating findings before emission.
- Anti-hallucination checks.

---

## 📁 System Prompts Directory Structure

```text
bugtrace/agents/system_prompts/
├── analysis_agent.md      # Multi-persona URL analysis (Pentester, Researcher, etc.)
├── dast_agent.md          # Vulnerability-specific analysis personas
├── xss_agent_v3.md        # Advanced XSS discovery and exploitation
├── url_master.md          # Orchestration logic for vertical agents
├── exploit_1.md           # Vision-based screenshot validation for ExploitAgent
├── recon_1.md             # Visual analysis and path prediction for ReconAgent
├── optic_validator.md     # Vision prompts for XSS, SQLi, and general validation
├── skeptic_1.md           # High-confidence XSS verification prompts
└── reporting_agent.md     # Impact and remediation enrichment
```

---

## 🛠️ Usage for Developers

### Adding/Modifying a Prompt

To change an agent's behavior, edit its corresponding `.md` file.

| Element | Description |
| :--- | :--- |
| **YAML Frontmatter** | Used for metadata (`name`, `version`) and structured config (`personas`, `golden_payloads`). |
| **System Prompt** | The bulk text after the second `---`. |
| **Placeholders** | Use `{url}`, `{params}`, `{context}` etc. replaced at runtime via `.format()`. |

### Agent Implementation Example

```python
class MyAgent(BaseAgent):
    def __init__(self, event_bus=None):
        super().__init__("MyAgent", "Specialist", event_bus=event_bus, agent_id="my_agent")
        
    async def run_loop(self):
        # self.system_prompt is already loaded here
        # self.agent_config contains parsed YAML parameters
        pass
```

---

## 🧪 Consistency & Validation

The externalized prompts adhere to the **XML-Like Output Protocol (RFC 001)**:

- Logic is wrapped in `<thought>` tags (hidden from reports).
- Final output is wrapped in structured tags like `<analysis>`, `<vulnerability>`, etc.
- This ensures robust parsing even with "chatty" or reasoning-heavy models (Qwen, DeepSeek).

---

Last Updated: 2026-01-12 | Version: v1.7.2
