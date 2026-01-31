# .ai-context - AI-Assisted Development Documentation

This directory contains context documentation designed to help AI assistants (like Claude, GPT, Gemini) understand the BugTraceAI codebase architecture and make informed contributions.

## What is this folder for?

When working with AI assistants on this codebase, you can reference files in this directory to provide the AI with architectural context, design decisions, and technical specifications. This helps ensure AI-generated code aligns with the existing architecture.

## Directory Structure

```
.ai-context/
├── README.md                      # This file
├── ARCHITECTURE_V4.md             # Current system architecture overview
├── BUGTRACE_MASTER_DOC.md         # Complete technical reference
├── PROJECT_STORYLINE.md           # Development history and evolution
├── QUICKSTART_GUIDE.md            # Getting started guide
├── report_generation_spec.md      # Report generation specification
│
├── architecture/                  # Architecture documentation
│   ├── phases.md                  # Pipeline phase conventions
│   └── diagrams.md                # System diagrams
│
├── technical_specs/               # Detailed technical specifications
│   ├── CDP_VS_PLAYWRIGHT_XSS.md   # XSS validation approaches
│   ├── feature_inventory.md       # Feature catalog
│   ├── REPORTING_SPEC.md          # Reporting system spec
│   └── WHY_VALIDATOR_FOR_XSS.md   # Validation design rationale
│
├── examples/                      # Code examples
│   └── code_examples.md           # API usage examples
│
└── roadmap/                       # Future development plans
    ├── README.md                  # Roadmap overview
    ├── 00-privacy-principles.md   # Privacy-first design
    ├── 01-observability.md        # Observability features
    └── ...                        # Additional roadmap items
```

## Key Documents

### For Understanding the Architecture

- **ARCHITECTURE_V4.md** - Start here for an overview of the current system design
- **BUGTRACE_MASTER_DOC.md** - Comprehensive technical reference
- **architecture/phases.md** - Understanding the 5-phase pipeline (Discovery → Evaluation → Exploitation → Validation → Reporting)

### For Contributing Code

- **examples/code_examples.md** - See how to use the API
- **technical_specs/** - Detailed specifications for specific subsystems
- **QUICKSTART_GUIDE.md** - Development setup and workflow

### For Planning Features

- **roadmap/** - Planned features and architectural direction
- **PROJECT_STORYLINE.md** - Historical context and evolution

## How to Use This with AI Assistants

When asking an AI to work on BugTraceAI code:

1. **Reference relevant docs**: "Using the architecture described in .ai-context/ARCHITECTURE_V4.md, implement..."
2. **Provide context**: "Following the patterns in .ai-context/technical_specs/REPORTING_SPEC.md, add..."
3. **Ensure alignment**: "Check .ai-context/roadmap/01-observability.md for planned observability features before implementing..."

## Maintaining This Documentation

- Keep architecture docs updated when making significant changes
- Add new specs to technical_specs/ when introducing new subsystems
- Update roadmap/ as features are completed or priorities change
- Examples should reflect current API usage patterns

---

**Note**: This folder is for AI context only. End-user documentation lives in the main `docs/` directory.
