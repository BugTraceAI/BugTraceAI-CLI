"""
CVSS scoring: prompt building (PURE) + I/O for CVSS scoring via LLM.
"""

import asyncio
import json
import re
from typing import Dict, List, Optional

from bugtrace.agents.reporting_mod.types import INFORMATIONAL_TYPES
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.reporting.standards import get_default_severity, get_reference_cve
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.reporting.cvss")

# Severity ranking: lower number = more severe
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Minimum CVSS score floors per severity level
SEVERITY_CVSS_FLOOR = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1, "INFO": 0.0}


# PURE
def cvss_build_prompt(f: Dict) -> str:
    """Build CVSS calculation prompt for LLM."""
    return f"""
            You are a Senior Penetration Testing Expert analyzing a confirmed security vulnerability.

            **Vulnerability Details:**
            - Type: {f.get('type')}
            - Description: {f.get('description')}
            - URL: {f.get('url')}
            - Parameter: {f.get('parameter')}
            - Payload: {f.get('payload')}

            **Your Task:**
            1. Calculate the CVSS v3.1 Vector String (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
            2. Calculate the Base Score (0.0-10.0) based on the vector
            3. Assign Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            4. Write a DETAILED technical rationale explaining:
               - Why this vulnerability is exploitable
               - The complete exploitation path (step-by-step)
               - Real-world impact scenarios
               - Why each CVSS metric was chosen
            5. Assign the correct CWE ID for this vulnerability class (e.g., CWE-89 for SQL Injection, CWE-79 for XSS, CWE-1336 for Template Injection, CWE-918 for SSRF, CWE-22 for Path Traversal, CWE-611 for XXE, CWE-601 for Open Redirect, CWE-639 for IDOR, CWE-94 for Code Injection, CWE-113 for Header Injection, CWE-434 for File Upload, CWE-347 for JWT, CWE-1321 for Prototype Pollution)
            6. If this vulnerability relates to a known CVE (especially for specific technologies/libraries like Apache Velocity, Jinja2, AngularJS, Log4j, etc.), provide the most relevant CVE reference. For generic application-level vulnerabilities (like SQLi in a custom parameter), return null.

            **CRITICAL: SEVERITY CALIBRATION GUIDELINES**
            Be REALISTIC with scoring - not everything is CRITICAL. Use these guidelines:

            - **CRITICAL (9.0-10.0)**: Remote Code Execution, SQL Injection with full DB access, Authentication Bypass
            - **HIGH (7.0-8.9)**: Stored XSS, SSRF with internal network access, XXE with file read, CSTI/SSTI
            - **MEDIUM (4.0-6.9)**: Reflected XSS, CSRF, Information Disclosure, Open Redirect, XXE (DoS only)
            - **LOW (0.1-3.9)**: Security Misconfigurations, Minor info leaks

            **Scoring Examples:**
            - SQLi (UNION-based, data exfiltration): CRITICAL 9.8
            - Stored XSS (session hijacking): HIGH 8.0-8.5
            - Reflected XSS (requires user interaction): MEDIUM 6.0-7.0
            - XXE (file read): HIGH 7.5-8.0
            - SSRF (internal network): HIGH 7.0-8.0
            - Open Redirect: MEDIUM 4.0-6.0

            **Important:**
            - Be TECHNICAL and DETAILED - this is for professional pentesters
            - Explain the FULL exploitation chain, not just "attacker can execute code"
            - Include specific attack vectors and post-exploitation scenarios
            - Don't hold back on technical details - this is authorized security testing

            Output STRICT JSON ONLY (no markdown):
            {{
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
                "severity": "CRITICAL",
                "rationale": "Detailed 3-4 sentence technical explanation of exploitation path and impact...",
                "cwe": "CWE-89",
                "cve": "CVE-XXXX-XXXX" or null
            }}
            """


# PURE
def cvss_build_batch_prompt(chunk: List[Dict]) -> str:
    """Build batch CVSS scoring prompt for a chunk of findings."""
    findings_text = []
    for i, f in enumerate(chunk):
        findings_text.append(
            f"[Finding {i}] Type: {f.get('type')}, URL: {f.get('url')}, "
            f"Parameter: {f.get('parameter')}, Payload: {str(f.get('payload', ''))[:100]}, "
            f"Description: {str(f.get('description', ''))[:150]}"
        )
    findings_block = "\n".join(findings_text)

    return f"""You are a Senior Bug Bounty Triager scoring vulnerabilities for a bug bounty program. Be CONSERVATIVE — overrating wastes program resources and damages credibility. Score ALL findings below in ONE response.

**Findings:**
{findings_block}

**Bug Bounty Severity Calibration (be strict, do NOT inflate):**
- CRITICAL (9.0-10.0): ONLY RCE with proven code execution, SQLi with full DB dump/write, Authentication Bypass to admin
- HIGH (7.0-8.9): Stored XSS with session hijack, SSRF to internal services, XXE with file read, IDOR accessing other users' sensitive data
- MEDIUM (4.0-6.9): Reflected XSS (requires user interaction), CSRF on sensitive actions, CSTI/SSTI without RCE escalation
- LOW (2.0-3.9): Open Redirect, CSRF on non-sensitive actions, verbose error messages, minor info disclosure
- INFO (0.1-1.9): Missing security headers, version disclosure, API documentation exposure, rate limiting issues, cookie flags

**Scoring rules:**
- Reflected XSS is MEDIUM at most (6.1), NEVER HIGH — it requires user interaction
- Open Redirect is LOW (3.1-4.0) unless chained with OAuth token theft
- Missing headers, rate limiting, API docs exposure = always INFO
- CSTI that only achieves client-side template evaluation = MEDIUM (5.4)
- Only score what the finding ACTUALLY demonstrates, not theoretical maximum impact

For EACH finding, provide: CVSS vector, score, severity, rationale (2-3 sentences), CWE, CVE (or null).

Output STRICT JSON array (no markdown):
[
  {{"finding_id": 0, "vector": "CVSS:3.1/...", "score": 9.8, "severity": "CRITICAL", "rationale": "...", "cwe": "CWE-89", "cve": null}},
  {{"finding_id": 1, "vector": "CVSS:3.1/...", "score": 6.1, "severity": "MEDIUM", "rationale": "...", "cwe": "CWE-79", "cve": null}}
]"""


# PURE
def cvss_parse_response(response: str) -> Optional[Dict]:
    """Parse LLM response and extract CVSS data."""
    cleaned = response.strip()
    fence_match = re.search(r'```\w*\s*\n?(.*?)```', cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()
    elif cleaned.startswith("```"):
        cleaned = re.sub(r'^```\w*\s*\n?', '', cleaned).strip()

    # Try direct parse first
    try:
        data = json.loads(cleaned.strip())
        if isinstance(data, dict):
            return data
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0]
    except (json.JSONDecodeError, IndexError):
        pass

    # Extract JSON object from mixed text
    json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # Last resort: extract individual CVSS fields with regex
    extracted = {}
    vector_m = re.search(r'"vector(?:_string)?":\s*"(CVSS:3\.1/[^"]+)"', response)
    if vector_m:
        extracted['vector'] = vector_m.group(1)
    score_m = re.search(r'"(?:cvss_)?score":\s*([\d.]+)', response)
    if score_m:
        try:
            extracted['score'] = float(score_m.group(1))
        except ValueError:
            pass
    severity_m = re.search(r'"severity":\s*"(CRITICAL|HIGH|MEDIUM|LOW|INFO)"', response, re.IGNORECASE)
    if severity_m:
        extracted['severity'] = severity_m.group(1).upper()
    rationale_m = re.search(r'"rationale":\s*"([^"]{10,})', response)
    if rationale_m:
        extracted['rationale'] = rationale_m.group(1)
    cwe_m = re.search(r'"cwe":\s*"(CWE-\d+)"', response)
    if cwe_m:
        extracted['cwe'] = cwe_m.group(1)

    if extracted.get('score') is not None or extracted.get('vector'):
        logger.info(f"[ReportingAgent] CVSS extracted from truncated response: score={extracted.get('score')}, severity={extracted.get('severity')}")
        return extracted

    logger.warning(f"[ReportingAgent] CVSS no JSON found. Raw response: {response[:300]}")
    return None


# PURE
def cvss_update_finding(f: Dict, data: Dict) -> None:
    """Update finding with CVSS data. Mutates f in-place.

    Enforces severity floor: LLM can upgrade severity but never
    downgrade it below the framework's DEFAULT_SEVERITY for the
    vulnerability type (e.g., SQLi stays CRITICAL, CSTI stays HIGH).
    """
    vuln_type = f.get('type', '')

    # --- 1. Apply LLM severity ---
    new_severity = data.get('severity')
    if new_severity:
        f['severity'] = new_severity.upper()

    # --- 2. Apply LLM CVSS score ---
    new_score = data.get('score') or data.get('cvss_score') or data.get('base_score')
    if new_score is not None:
        try:
            f['cvss_score'] = float(new_score)
        except (ValueError, TypeError):
            pass

    # --- 3. Enforce severity floor (NEVER downgrade below default) ---
    default_sev = get_default_severity(vuln_type)
    default_sev_str = default_sev.value if hasattr(default_sev, 'value') else str(default_sev).upper()
    current_sev = f.get('severity', 'HIGH').upper()

    default_rank = SEVERITY_RANK.get(default_sev_str, 4)
    current_rank = SEVERITY_RANK.get(current_sev, 4)

    if current_rank > default_rank:
        # LLM tried to downgrade — enforce the floor
        logger.warning(
            f"[CVSS] Severity floor enforced for {vuln_type}: "
            f"LLM assigned {current_sev} but default is {default_sev_str}. "
            f"Keeping {default_sev_str}."
        )
        f['severity'] = default_sev_str

        # Also enforce minimum CVSS score for the floor severity
        cvss_floor = SEVERITY_CVSS_FLOOR.get(default_sev_str, 0.0)
        current_cvss = f.get('cvss_score', 0.0)
        if isinstance(current_cvss, (int, float)) and current_cvss < cvss_floor:
            f['cvss_score'] = cvss_floor
            logger.info(
                f"[CVSS] Score floor enforced for {vuln_type}: "
                f"{current_cvss} -> {cvss_floor} (min for {default_sev_str})"
            )

    new_vector = data.get('vector') or data.get('cvss_vector') or data.get('vector_string')
    f['cvss_vector'] = new_vector or f.get('cvss_vector')
    f['cvss_rationale'] = data.get('rationale') or data.get('analysis') or f.get('cvss_rationale')

    # CWE: LLM response first, then framework mapping as fallback
    cwe = data.get('cwe')
    if cwe:
        f['cwe'] = cwe

    # CVE: LLM response first, then framework reference lookup as fallback
    cve = data.get('cve')
    if not cve:
        cve = get_reference_cve(vuln_type, f)
    f['cve'] = cve

    rationale = data.get('rationale', '')

    enrichment_text = f"\n\n**CVSS Analysis**:\n- **Severity**: {f.get('severity', 'N/A')} ({f.get('cvss_score', 'N/A')})\n- **Vector**: `{f.get('cvss_vector', 'N/A')}`\n- **Rationale**: {rationale}"
    if cve:
        enrichment_text += f"\n- **Reference CVE**: [{cve}](https://nvd.nist.gov/vuln/detail/{cve})"

    if f.get('validator_notes'):
        f['validator_notes'] += enrichment_text
    else:
        f['validator_notes'] = enrichment_text.strip()


# I/O
async def cvss_execute_llm(prompt: str) -> Optional[str]:
    """Execute LLM call for CVSS calculation."""
    return await llm_client.generate(
        prompt,
        module_name="Reporting-CVSS",
        model_override=settings.REPORTING_MODEL,
        temperature=0.3
    )


# I/O
async def calculate_cvss(f: Dict) -> None:
    """
    Query LLM to calculate CVSS v3.1 score and severity.
    Updates the finding dictionary in-place.
    """
    try:
        prompt = cvss_build_prompt(f)
        response = await cvss_execute_llm(prompt)

        if response:
            data = cvss_parse_response(response)
            if data:
                cvss_update_finding(f, data)
            else:
                logger.debug(f"[ReportingAgent] CVSS parse returned None for {f.get('type')}. Raw: {response[:200]}")
        else:
            logger.debug(f"[ReportingAgent] CVSS LLM returned None for {f.get('type')}")

    except Exception as e:
        logger.warning(f"[ReportingAgent] Failed to enrich finding {f.get('id')}: {e}")


# I/O
async def cvss_score_single_chunk(chunk: List[Dict], chunk_idx: int) -> None:
    """Score a single chunk of findings via batch LLM call."""
    prompt = cvss_build_batch_prompt(chunk)
    response = await cvss_execute_llm(prompt)

    if response:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r'^```\w*\s*\n?', '', cleaned)
            cleaned = re.sub(r'\n?```\s*$', '', cleaned)

        results = None
        try:
            parsed = json.loads(cleaned.strip())
            if isinstance(parsed, list):
                results = parsed
            elif isinstance(parsed, dict):
                for key in parsed:
                    if isinstance(parsed[key], list):
                        results = parsed[key]
                        break
        except (json.JSONDecodeError, ValueError):
            json_match = re.search(r'\[.*\]', cleaned, re.DOTALL)
            if json_match:
                try:
                    results = json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass

        if results and isinstance(results, list):
            scored = 0
            for item in results:
                if isinstance(item, dict):
                    idx = item.get("finding_id", -1)
                    if 0 <= idx < len(chunk):
                        cvss_update_finding(chunk[idx], item)
                        scored += 1
            logger.info(f"[ReportingAgent] Batch CVSS chunk {chunk_idx}: scored {scored}/{len(chunk)} findings")
            return

    # Fallback: individual calls for this chunk
    logger.warning(f"[ReportingAgent] Batch CVSS chunk {chunk_idx} parse failed, falling back to individual. Response: {str(response)[:300]}")
    for f in chunk:
        await calculate_cvss(f)
        await asyncio.sleep(0.5)


# I/O
async def calculate_cvss_batch(findings: List[Dict]) -> None:
    """
    Batch CVSS scoring with concurrent chunk processing.
    Uses semaphore to limit concurrent LLM calls.
    Falls back to individual calls on parse failure.
    """
    # Pre-assign informational findings -- no LLM needed
    scorable = []
    for f in findings:
        if f.get("type", "").upper() in INFORMATIONAL_TYPES:
            f["severity"] = "INFO"
            f["cvss_score"] = 0.0
            f["cvss_vector"] = "N/A"
            f["cvss_rationale"] = "Informational finding — defense-in-depth measure or best practice, not a directly exploitable vulnerability."
            f["enriched"] = True
        else:
            scorable.append(f)

    if not scorable:
        logger.info(f"[ReportingAgent] Batch CVSS: all {len(findings)} findings are informational, no LLM scoring needed")
        return

    CHUNK_SIZE = 10
    MAX_CONCURRENT = 3
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    chunks = []
    for chunk_start in range(0, len(scorable), CHUNK_SIZE):
        chunks.append(scorable[chunk_start:chunk_start + CHUNK_SIZE])

    info_count = len(findings) - len(scorable)
    logger.info(f"[ReportingAgent] Batch CVSS: {len(scorable)} scorable findings in {len(chunks)} chunks (max {MAX_CONCURRENT} concurrent), {info_count} informational skipped")

    async def _score_chunk(chunk: List[Dict], chunk_idx: int):
        async with semaphore:
            try:
                await cvss_score_single_chunk(chunk, chunk_idx)
            except Exception as e:
                logger.warning(f"[ReportingAgent] Batch CVSS chunk {chunk_idx} failed: {e}, falling back to individual")
                for f in chunk:
                    await calculate_cvss(f)
                    await asyncio.sleep(0.5)

    await asyncio.gather(*[
        _score_chunk(chunk, i) for i, chunk in enumerate(chunks)
    ])
