# PROPOSED ARCHITECTURE REFACTOR: "V3.5 Reactor" (Naming & Logic Fix)

## 1. Context & Motivation

The current "Hunter/Manager" nomenclature is functional but functionally ambiguous. "Manager" confusingly implies coordination rather than its actual role of strict validation. Furthermore, a critical logical flaw has been identified where discovery agents (Hunters) hallucinate conversational payloads instead of executable attack strings, causing downstream validation failures.

This plan addresses both the naming convention (for clarity) and the logical integrity of the payload pipeline.

---

## 2. Naming Convention Refactor

We propose aligning the framework terminology with professional Red Teaming roles to better reflect the purpose of each phase.

| Previous Name | **New Name** | Explanation |
| :--- | :--- | :--- |
| **Hunter Phase** | **(No Change) Hunter Phase** | "Hunter" accurately describes proactive discovery and attack surface mapping. |
| **Manager Phase** | **Auditor Phase** | "Auditor" correctly describes the role: reviewing, verifying, and validating findings. It implies judgement and precision. |
| **Reporter Phase** | **(No Change) Reporter Phase** | Self-explanatory. |

### Codebase Changes Required

1. **CLI Commands**:
    * `audit` command remains (it fits the new name perfectly).
    * Descriptions in CLI help text updated: "Run the Audit (Manager) phase" -> "Run the Audit (Auditor) phase".
2. **Logging**:
    * `[Manager]` prefix in logs -> `[Auditor]` or `[Validator]`.
3. **Documentation**:
    * Update `ARCHITECTURE_V3.md` and related context files.

---

## 3. Logical Fix: The "Raw Payload" Directive

**Problem:** Discovery Agents (e.g., XSSAgent) are currently returning "conversational" payloads like:
> *"Inject <script>...</script> to verify this..."*

**Impact:** The Auditor (Validator) takes this string literally, injects it, and fails because the browser renders it as harmless text.

**Solution:** Enforce a strict **"Raw Payload Protocol"** for all Discovery Agents.

### Action Plan

1. **Update Discovery Agent System Prompts**:
    * Add explicit negative constraints: "NEVER include instructional text content in the payload field."
    * "The payload field must be EXECUTABLE code only."
2. **Update `Conductor` Validation**:
    * Add a pre-flight check in the Conductor that rejects payloads containing conversational markers (e.g., "Inject", "Try", "Use").
3. **Sanatize Existing Findings (Migration)**:
    * (Optional) If resuming a scan, a script should clean existing "dirty" payloads in the DB.

---

## 4. Implementation Steps

1. **Refactor Names** in `bugtrace/__main__.py` and `ARCHITECTURE_V3.md`.
2. **Update Prompts** for `XSSAgent`, `SQLiAgent`, etc., in `bugtrace/agents/system_prompts/`.
3. **Verify** with a new scan on the validation Dojo (`dojo_validation.py`) to confirm payloads are clean and validation succeeds.
4. **Final Polish**: Ensure the report reflects the new terminology.

---

**Status:** Ready for User Review.
