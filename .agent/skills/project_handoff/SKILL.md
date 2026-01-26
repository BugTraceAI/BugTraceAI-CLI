---
name: project_handoff
description: Generates a standardized handoff document for the BugTraceAI project, ensuring all context is preserved between sessions. Use this when the user asks to "prepare a handoff", "save state", or "end the session".
---

# Project Handoff Skill

This skill helps you generate a standardized handoff document compliant with the BugTraceAI team's conventions.

## 1. Naming Convention

The filename MUST follow this pattern:
`GEMINI_HANDOFF_[TOPIC]_[YYYY-MM-DD].md`

- **TOPIC**: Short, uppercase descriptor of the main work done (e.g., `REPORTING_FIX`, `SQLI_OPTIMIZATION`).
- **Date**: Current date in YYYY-MM-DD format.

**Location**: All handoffs must be saved in `.ai-context/handoffs/`.

## 2. Document Structure

The markdown content MUST follow this template:

```markdown
# Handoff: [Readable Title of What Was Done]
**Date**: [YYYY-MM-DD]
**Author**: [Your Model Name, e.g., Antigravity]

## 1. Executive Summary
[Brief 2-3 sentence summary of the main achievements and current status.]

## 2. Technical Changes Implemented
- **[Component Name]**: [Description of change]
  - [Detail 1]
  - [Detail 2]
- **[File Modified]**: [What was changed and why]

## 3. Verification & Testing
- **Tests Run**: [List tests executed]
- **Results**: [Pass/Fail status]
- **Evidence**: [Mention specific log files or artifacts generated]

## 4. Known Issues / Blockers
- [Issue 1]: [Description]
- [Issue 2]: [Description]

## 5. Next Steps (Immediate Action Items)
1. [Step 1]
2. [Step 2]
3. [Step 3]
```

## 3. Capabilities & Helper Scripts

Currently this skill relies on your internal knowledge to summarize the session.
In the future, it may invoke scripts to auto-gather git diffs.

## 4. Instructions for the Agent

1. **Analyze Session**: Review the conversation history to identify completed tasks, modified files, and pending items.
2. **Determine Topic**: Select a concise topic name for the filename.
3. **Draft Content**: Fill in the template above.
4. **Save File**: Use `write_to_file` to save the document to `.ai-context/handoffs/`.
5. **Language**: Ensure the entire handoff report is written in **ENGLISH**.
6. **Confirm**: Tell the user the handoff has been saved and provide the path.
