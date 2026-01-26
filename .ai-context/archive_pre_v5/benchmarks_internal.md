# Internal Benchmarks and Inspirations (Developer Only)

This document contains internal references and competitive benchmarks. **DO NOT EXPORT TO PUBLIC GITHUB.**

## Inspirations and Benchmarks
BugtraceAI-CLI was originally positioned to compete with and exceed the capabilities of several state-of-the-art AI pentesting frameworks:

*   **PentAGI**: Benchmarked for **Memory** (GraphRAG). BugtraceAI aims to exceed its persistence capabilities using LanceDB and NetworkX.
*   **Strix**: Benchmarked for **Visuals**. BugtraceAI uses Playwright + vLM (Vision Models) to enhance the visual XSS detection patterns popularized by Strix.
*   **Guardian**: Benchmarked for **Production Readiness**. v1.6.0 focuses on achieving and exceeding this level of enterprise-scale robustness.

## Architecture References
- **shift-agents-v2**: The HTTP Manipulator logic for mutation and WAF bypass is inspired by this research.
