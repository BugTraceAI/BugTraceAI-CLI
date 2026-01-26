# Architecture Upgrade: Modular Skill Injection System

## 🌟 Overview

Inspired by leading autonomous AI security projects like **Strix** and **Decepticon**, BugTraceAI has transitioned from a monolithic prompt architecture to a **Modular Skill Injection System**. This allows specialized security knowledge to be dynamically "injected" into any agent based on the target's technology stack and the specific vulnerability context.

## 🛠️ Technical Implementation

### 1. BaseAgent Skill Loader

The `BaseAgent` class now includes a dynamic loader that reads YAML frontmatter from agent prompt files. If a `skills` list is defined, the agent automatically fetches the corresponding knowledge base from `/bugtrace/agents/skills/`.

**How it works:**

- **Discovery**: When an agent (e.g., `XSSAgent`) initializes, it reads its Markdown prompt.
- **Extraction**: It parses the YAML headers to find required skills.
- **Injection**: It appends the content of these skills to the system prompt before interacting with the LLM.

### 2. Expert Knowledge Repositories (`/bugtrace/agents/skills/`)

We have established a new directory for "Deep Knowledge" modules:

- **`frameworks.md`**:
  - Contains specific attack and bypass patterns for modern JS frameworks (**React, Vue, Angular, Svelte**).
  - Includes logic for **Client-Side Template Injection (CSTI)** in legacy and modern environments.
- **`vulnerabilities.md`**:
  - A technical deep-dive into complex bypasses.
  - **XSS**: Coverage for Mutation XSS (mXSS), SVG/MathML polyglots, and context-specific encoding.
  - **SQLi**: Specialized knowledge for JSON/JSONB operators in Postgres and MySQL JSON functions.
  - **GraphQL**: Introspection and argument injection patterns.

## 🧠 Influence from Top-Tier Projects

### Learning from Strix (usestrix/strix)

- **Modular Methodology**: We adopted their "Context + Sink" approach. Instead of brute-forcing payloads, agents now classify the injection context first (HTML text, attribute, JS string, etc.) and then select the appropriate skill module.
- **Attacker Persistence**: We implemented the "Persistence is Mandatory" rule. Agents are now instructed to expect 2000+ steps for complex targets, mimicking a human pentester.

### Learning from Decepticon (PurpleAILAB/Decepticon)

- **Knowledge Packaging**: Following their "Vibe Hacking" philosophy, we now package intelligence (like discovered tech stacks) so it can be consumed as a "Skill" by subsequent agents in the execution chain.

## 🚀 Impact on XSSAgentV4

The XSS Agent is the first to be fully upgraded with this system:

- **Automatic Scaling**: It doesn't just "know" XSS; it "knows" how to break **Angular Sandbox** or **React's dangerouslySetInnerHTML** because it loads the `frameworks` skill.
- **PoE Excellence**: By loading the `vulnerabilities` skill, it prioritizes **Visual Defacement** and **Loot Extraction** (Cookies/JWTs) over simple alerts.

## 📁 File Structure

```text
bugtrace/
  agents/
    base.py (Updated with Skill Loader)
    system_prompts/
      xss_agent.md (Configured with YAML skills)
    skills/
      frameworks.md (New Knowledge Base)
      vulnerabilities.md (New Knowledge Base)
```

**Status**: ✅ IMPLEMENTED & DOCUMENTED (v1.7.5)
