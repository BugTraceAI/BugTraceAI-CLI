# BugTraceAI Dojo & Lab Guide

This document maps the different testing environments available in the project and their specific purposes.

## 🥊 The Gauntlets (Complex Environments)

### 1. Ultimate Boss: Mega Mixed Gauntlet

* **File:** `testing/dojos/dojo_benchmark.py`
* **Port:** `5150`
* **Topography:** 20+ URLs with high-level vulnerabilities (Levels 7-10).
* **Purpose:** Designed to test the **Surgical Orchestrator** and **Agent Task Handoffs**. It probes the system's ability to handle complex, multi-layered security (WAFs, CSPs, Filter Bypasses) and ensures the framework doesn't give up on difficult targets.

### 2. Comprehensive Dojo (Individual Agent Benchmarking)

* **File:** `testing/dojos/dojo_training.py`
* **Port:** `5090`
* **Topography:** Independent URLs for each level (0-10) and vulnerability type (XSS, SQLi, SSRF, XXE, etc.).
* **Purpose:** The primary environment for **Individual Agent Scoring**. It is designed to test how deep an agent can go independently.
* **Scoring System:**
  * **L0-L2:** Basic functionality (Basics).
  * **L3-L5:** Filter bypasses (Intermediate).
  * **L6-L7:** **Frame Target** (Advanced WAF/CSP/Filters). Success here defines a "Production Ready" agent.
  * **L8-L10:** Expert/Research levels (mXSS, Polyglots, Second-Order).

---

## 🧪 The Labs (Reporting & Traceability)

### 1. Simple Reporting Lab

* **Files:** `lab/app.py` (Flask) and `lab/server.py` (HTTP Server)
* **Ports:** `5005` (Flask) / `5006` (Server)
* **Topography:** Just 2 URLs (Upload form and File viewer).
* **Purpose:** Specifically designed for **Reporting Validation**. Its simplicity allows for 100% noise-free testing of the `AgenticValidator` and `ReportingAgent`. Use this to verify that PoCs, screenshots, and reproduction steps are perfectly captured in the final reports.

### 2. Orchestration Training (Basic)

* **File:** `testing/dojos/dojo_basic.py`
* **Port:** `5100`
* **Topography:** 10 curated challenges mixing different vulnerabilities.
* **Purpose:** A mid-point between labs and gauntlets. Good for testing general orchestration flow without the extreme complexity of the Mega Gauntlet.

---

## 🚀 Quick Execution

To run a dojo, use:

```bash
python3 testing/dojos/[filename].py
```

Or use the `testing/dojos/dojo_validation.py` script to run automated tests against them.
