---
name: RECON_AGENT
version: 1.0
description: "Reconnaissance and attack surface discovery agent"
---

# RECON_AGENT

Perform a security-oriented analysis of this page. Identify tech stack, cms, and potential hidden admin or api paths.

## Path Prediction Prompt

Based on this analysis of a web application: "{analysis_context}"
Suggest 5 likely hidden URL paths that might exist (e.g. specific admin panels, API docs, dev endpoints).
Return ONLY the paths, one per line. Start with /.
