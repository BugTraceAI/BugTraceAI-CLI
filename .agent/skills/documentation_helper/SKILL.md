---
name: documentation_helper
description: Expert technical writer for BugTraceAI. Maintains project docs (`.ai-context`), updates READMEs, and generates docstrings. Use this skill when the user asks to "update docs", "document this feature", or "explain what changed".
---

# Documentation Helper Skill

This skill ensures that the documentation remains in sync with the code, specifically updating the `.ai-context` to reflect real-time changes.

## 1. Documentation Types

### A. Context Files (`.ai-context/*.md`)

These are the most critical files for your memory.

- **`ARCHITECTURE_V3.md`**: Update this if core flows change (e.g., new Reactor phase).
- **`PROJECT_STORYLINE.md`**: Append new major achievements here (e.g., "Implemented JWT Agent").
- **`technical_specs/`**: If a new module is built, create a spec here (e.g., `technical_specs/jwt_lookup.md`).

### B. User-Facing Docs

- **`README.md`**: Update installation steps or new CLI flags.
- **Docstrings**: Ensure every new class has standard Python docstrings (Google Style).

## 2. Documentation Rules

1. **Be Honest**: Do not document "planned" features as "completed". Only document what works.
2. **Link Code**: When mentioning a class, put the path in backticks: `` `bugtrace/core/reactor.py` ``.
3. **Update Date**: Always update the "Last Updated" or date fields in the document header.

## 3. Instructions for the Agent

1. **Identify the Scope**: What changed? (A new CLI flag? A new Agent? A bug fix?)
2. **Select Target**:
   - Small fix -> `PROJECT_STORYLINE.md` entry.
   - New Feature -> New file in `.ai-context/technical_specs/` AND update `ARCHITECTURE_V3.md` if needed.
3. **Draft & Write**: Use `write_to_file` to update the markdown.
4. **Clean Up**: If replacing an old spec, move the old one to `.ai-context/archive/`.
