"""
PURE functions for LLM prompt construction and response parsing.

All functions depend only on their arguments.  No network I/O.
"""
from typing import Dict, List, Optional

from loguru import logger

from bugtrace.utils.parsers import XmlParser
from bugtrace.agents.dastysast.probing import format_probe_evidence


# =========================================================================
# Prompt building
# =========================================================================

def build_analysis_prompt(
    url: str,
    tech_profile: Dict,
    context: Dict,
    skill_context: str,
) -> str:
    """
    Build the main analysis prompt with context and active probe results.

    Args:
        url:           Target URL.
        tech_profile:  Technology profile dict.
        context:       Prepared analysis context.
        skill_context: Extra skill-specific context from the loader.

    Returns:
        Complete prompt string.
    """  # PURE
    probe_section = format_probe_evidence(context.get("reflection_probes", []))

    tech_info_parts: List[str] = []
    if tech_profile.get("infrastructure"):
        tech_info_parts.append(f"Infrastructure: {', '.join(tech_profile['infrastructure'])}")
    if tech_profile.get("frameworks"):
        tech_info_parts.append(f"Frameworks: {', '.join(tech_profile['frameworks'])}")
    if tech_profile.get("servers"):
        tech_info_parts.append(f"Servers: {', '.join(tech_profile['servers'])}")
    if tech_profile.get("waf"):
        tech_info_parts.append(f"WAF Detected: {', '.join(tech_profile['waf'])}")
    if tech_profile.get("cdn"):
        tech_info_parts.append(f"CDN: {', '.join(tech_profile['cdn'])}")

    tech_stack_summary = (
        "\n".join(tech_info_parts)
        if tech_info_parts
        else "Basic web application (no specific technologies detected)"
    )

    return f"""Analyze this URL for security vulnerabilities.

URL: {url}

=== TECHNOLOGY STACK (Use this to craft precise exploits) ===
{tech_stack_summary}

NOTE: Use detected technologies to:
- Generate version-specific exploits (e.g., AngularJS 1.7.7 CSTI bypasses)
- Identify infrastructure-specific attack vectors (e.g., AWS ALB header manipulation)
- Avoid wasting time on irrelevant attacks (e.g., PHP attacks on Node.js)
- Craft payloads that bypass detected WAF/CDN protections

=== ACTIVE RECONNAISSANCE RESULTS (MANDATORY EVIDENCE) ===
{probe_section if probe_section else "No parameters detected in URL."}

=== PAGE HTML SOURCE (Snippet) ===
{context.get('html_content', 'Not available')[:8000]}

=== ANALYSIS RULES (STRICT - NO SMOKE ALLOWED) ===

MANDATORY: Base your analysis ONLY on the probe results above.
- If a parameter REFLECTS, specify the EXACT context (html_text, html_attribute, script_block, url_context)
- If characters like < > " ' survive, that is EVIDENCE of XSS potential
- If NO reflection is detected, you CANNOT claim XSS - the parameter does NOT reflect

CONFIDENCE SCORING (Evidence-Based):
- 0-3: No probe evidence, speculation only -> DO NOT REPORT
- 4-5: Reflection detected but chars are encoded -> Low priority
- 6-7: Reflection in dangerous context (attribute/script) with some chars surviving
- 8-9: Reflection with < > " ' all surviving in dangerous context
- 10: Confirmed execution (script block with unfiltered input)

=== PROHIBITED (Will be rejected) ===
- "Could be vulnerable" without probe evidence
- "Potentially exploitable" without concrete context
- XSS claims on parameters that DO NOT reflect
- SQLi claims without error response or behavioral evidence
- Vague descriptions like "try injecting", "test for", "might work"

=== REQUIRED OUTPUT FORMAT ===

For EACH vulnerability, you MUST provide:
- html_evidence: The EXACT line/snippet where the vulnerability exists (from probe results)
- xss_context: For XSS, specify ONE OF: html_text, html_attribute, script_block, url_context, none
- chars_survive: Which special chars survive unencoded (< > " ' `)

OOB Callback: {context.get('oob_info', {}).get('callback_url', 'http://oast.fun')}

{f"=== SPECIALIZED KNOWLEDGE ==={chr(10)}{skill_context}{chr(10)}" if skill_context else ""}

OUTPUT FORMAT (XML):
<vulnerabilities>
  <vulnerability>
    <type>XSS (Reflected)</type>
    <parameter>search</parameter>
    <confidence_score>8</confidence_score>
    <xss_context>html_attribute</xss_context>
    <html_evidence>Line 47: &lt;input value="bugtraceomni7x9z"&gt;</html_evidence>
    <chars_survive>&lt; &gt; "</chars_survive>
    <reasoning>Parameter reflects in input value attribute at line 47. Chars &lt; &gt; survive unencoded.</reasoning>
    <severity>High</severity>
    <payload>" onfocus=alert(1) autofocus="</payload>
  </vulnerability>
</vulnerabilities>

Return ONLY valid XML tags. No markdown. No explanations.
"""


def build_skeptical_prompt(url: str, prior_findings: List[Dict]) -> str:
    """
    Build prompt for the skeptical agent review of prior findings.

    Args:
        url:            Target URL.
        prior_findings: Findings from core approaches.

    Returns:
        Complete prompt string.
    """  # PURE
    findings_summary: List[str] = []
    for i, f in enumerate(prior_findings):
        findings_summary.append(
            f"{i + 1}. {f.get('type', 'Unknown')} on '{f.get('parameter', 'unknown')}' "
            f"(confidence: {f.get('confidence_score', 5)}/10)\n"
            f"   Reasoning: {f.get('reasoning', 'No reasoning')[:200]}"
        )

    return f"""Review these vulnerability findings and identify FALSE POSITIVES:

=== TARGET ===
URL: {url}

=== FINDINGS TO REVIEW ({len(prior_findings)} total) ===
{chr(10).join(findings_summary)}

=== YOUR TASK ===
For EACH finding, assign a SKEPTICAL_SCORE (0-10):
- 0-3: LIKELY FALSE POSITIVE (reject)
- 4-5: UNCERTAIN (needs validation)
- 6-7: PLAUSIBLE (investigate)
- 8-10: LIKELY TRUE POSITIVE (high priority)

Return XML:
<skeptical_review>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <skeptical_score>3</skeptical_score>
    <fp_reason>Based on parameter name only, no evidence of reflection</fp_reason>
  </finding>
</skeptical_review>

Be RUTHLESS. False positives waste resources."""


def build_review_prompt(
    url: str, vulnerabilities: List[Dict]
) -> str:
    """
    Build the final skeptical review prompt with scoring guides.

    Args:
        url:              Target URL.
        vulnerabilities:  Pre-filtered vulnerability dicts.

    Returns:
        Complete prompt string.
    """  # PURE
    from bugtrace.agents.skills.loader import get_scoring_guide, get_false_positives

    parts: List[str] = []
    for i, v in enumerate(vulnerabilities):
        vuln_type = v.get("type", "Unknown")
        scoring_guide = get_scoring_guide(vuln_type)
        fp_guide = get_false_positives(vuln_type)

        part = (
            f"{i + 1}. {vuln_type} on '{v.get('parameter')}'\n"
            f"   DASTySAST Score: {v.get('confidence_score', 5)}/10 | "
            f"Votes: {v.get('votes', 1)}/5\n"
            f"   Reasoning: {v.get('reasoning') or 'No reasoning'}\n"
            f"\n"
            f"   {scoring_guide[:500] if scoring_guide else ''}\n"
            f"   {fp_guide[:300] if fp_guide else ''}"
        )
        parts.append(part)

    vulns_summary = "\n\n".join(parts)

    return f"""You are a security expert reviewing vulnerability findings.

=== TARGET ===
URL: {url}

=== FINDINGS ({len(vulnerabilities)} total) ===
{vulns_summary}

=== YOUR TASK ===
For EACH finding, evaluate and assign a FINAL CONFIDENCE SCORE (0-10).

SCORING GUIDE:
- 0-3: REJECT - No evidence, parameter name only, "EXPECTED: SAFE" present
- 4-5: LOW - Weak indicators, probably false positive
- 6-7: MEDIUM - Some patterns, worth testing by specialist
- 8-9: HIGH - Clear evidence (SQL errors, unescaped reflection)
- 10: CONFIRMED - Obvious vulnerability

RULES:
1. If the "DASTySAST Score" is high AND "Votes" are 4/5 or 5/5, lean towards a higher FINAL SCORE (6+).
2. Parameter NAME alone (webhook, id, xml) is NOT enough for score > 5, UNLESS votes are 5/5.
3. If "EXPECTED: SAFE" is found in reasoning, REJECT immediately (score 0-3).
4. "EXPECTED: VULNERABLE" in context -> score 8-10
5. SQL errors visible -> score 8+
6. Unescaped HTML reflection -> score 7+
7. Adjust DASTySAST score up/down based on your analysis

Return XML:
<reviewed>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <final_score>7</final_score>
    <reasoning>Brief explanation</reasoning>
  </finding>
</reviewed>
"""


def get_skeptical_system_prompt() -> str:
    """
    Return the system prompt for the skeptical_agent approach.

    Returns:
        System prompt string.
    """  # PURE
    return """You are a SKEPTICAL security auditor. Your job is to CHALLENGE vulnerability findings and identify FALSE POSITIVES.

SKEPTICAL MINDSET:
- Parameter names alone (id, user, file) are NOT evidence of vulnerability
- Generic patterns without concrete evidence are likely false positives
- Error messages must be SPECIFIC SQL/command errors, not generic 500s
- XSS requires UNESCAPED reflection in dangerous contexts, not just reflection
- WAF-blocked requests indicate the app HAS protections

FALSE POSITIVE INDICATORS:
- "Could be vulnerable" or "potentially" without concrete evidence
- Vulnerability based on parameter NAME only (id -> SQLi assumption)
- No specific payload that would trigger the issue
- Technology stack inference without actual testing
- Assumptions based on common patterns

LIKELY TRUE POSITIVE INDICATORS:
- Specific error messages (SQL syntax errors, stack traces)
- Unescaped user input in script/event handler contexts
- Demonstrated behavioral differences (time-based, boolean-based)
- OOB callbacks received
- Specific version with known CVE

For EACH potential vulnerability, assign a SKEPTICAL_SCORE:
- 0-3: LIKELY FALSE POSITIVE - Reject, based on weak evidence
- 4-5: UNCERTAIN - Could be either, needs specialist validation
- 6-7: PLAUSIBLE - Some evidence, worth specialist investigation
- 8-10: LIKELY TRUE POSITIVE - Strong evidence, high priority

REMEMBER: Being skeptical SAVES TIME. False positives waste specialist agent resources."""


# =========================================================================
# Response parsing
# =========================================================================

def parse_approach_response(response: str) -> Dict:
    """
    Parse an LLM response into a ``{"vulnerabilities": [...]}`` dict.

    Args:
        response: Raw XML response from the LLM.

    Returns:
        Dict with ``vulnerabilities`` key.
    """  # PURE
    parser = XmlParser()
    vuln_contents = parser.extract_list(response, "vulnerability")

    vulnerabilities: List[Dict] = []
    for vc in vuln_contents:
        vuln = parse_single_vulnerability(parser, vc)
        if vuln:
            vulnerabilities.append(vuln)

    return {"vulnerabilities": vulnerabilities}


def parse_single_vulnerability(parser: XmlParser, vc: str) -> Optional[Dict]:
    """
    Parse a single ``<vulnerability>`` XML block.

    Args:
        parser: XmlParser instance.
        vc:     Raw XML content of one ``<vulnerability>`` block.

    Returns:
        Parsed vulnerability dict, or ``None`` on failure.
    """  # PURE
    try:
        conf = parse_confidence_score(parser, vc)
        payload = (
            parser.extract_tag(vc, "payload", unescape_html=True)
            or parser.extract_tag(vc, "exploitation_strategy", unescape_html=True)
            or ""
        )

        return {
            "type": parser.extract_tag(vc, "type") or "Unknown",
            "parameter": parser.extract_tag(vc, "parameter") or "unknown",
            "confidence_score": conf,
            "reasoning": parser.extract_tag(vc, "reasoning") or "",
            "severity": parser.extract_tag(vc, "severity") or "Medium",
            "exploitation_strategy": payload,
        }
    except Exception as ex:
        logger.warning(f"Failed to parse vulnerability entry: {ex}")
        return None


def parse_confidence_score(parser: XmlParser, vc: str) -> int:
    """
    Parse and clamp a confidence score from XML.

    Args:
        parser: XmlParser instance.
        vc:     Raw XML content.

    Returns:
        Integer score in 0--10.
    """  # PURE
    conf_str = (
        parser.extract_tag(vc, "confidence_score")
        or parser.extract_tag(vc, "confidence")
        or "5"
    )
    try:
        conf = int(float(conf_str))
        return max(0, min(10, conf))
    except (ValueError, TypeError):
        return 5


def parse_skeptical_response(
    response: str, prior_findings: List[Dict], agent_name: str = "DASTySAST"
) -> Dict:
    """
    Parse the skeptical review response and attach scores to findings.

    Args:
        response:       Raw XML response from skeptical LLM.
        prior_findings: Findings that were submitted for review.
        agent_name:     Agent name for log context.

    Returns:
        Dict with ``vulnerabilities`` key and optional ``approach`` key.
    """  # PURE
    parser = XmlParser()
    finding_blocks = parser.extract_list(response, "finding")

    scored_findings: List[Dict] = []

    for block in finding_blocks:
        try:
            idx = int(parser.extract_tag(block, "index")) - 1
            if 0 <= idx < len(prior_findings):
                finding = prior_findings[idx].copy()
                finding["skeptical_score"] = int(
                    parser.extract_tag(block, "skeptical_score") or "5"
                )
                finding["fp_reason"] = parser.extract_tag(block, "fp_reason") or ""
                scored_findings.append(finding)
        except (ValueError, IndexError) as e:
            logger.warning(f"Failed to parse skeptical finding: {e}")

    logger.info(
        f"[{agent_name}] Skeptical review: {len(scored_findings)} findings scored"
    )
    return {"vulnerabilities": scored_findings, "approach": "skeptical_agent"}


def parse_review_approval(
    response: str,
    vulnerabilities: List[Dict],
    settings_get_threshold,
    agent_name: str = "DASTySAST",
) -> List[Dict]:
    """
    Parse the final skeptical review response and return approved findings.

    Args:
        response:               Raw XML response.
        vulnerabilities:        Submitted findings.
        settings_get_threshold: Callable(vuln_type: str) -> int returning threshold.
        agent_name:             Agent name for log context.

    Returns:
        List of approved finding dicts.
    """  # PURE
    parser = XmlParser()
    finding_blocks = parser.extract_list(response, "finding")

    approved: List[Dict] = []

    for block in finding_blocks:
        try:
            idx = int(parser.extract_tag(block, "index")) - 1
            vuln_type = parser.extract_tag(block, "type") or "UNKNOWN"
            final_score = int(parser.extract_tag(block, "final_score") or "0")
            reasoning = parser.extract_tag(block, "reasoning") or ""

            if not (0 <= idx < len(vulnerabilities)):
                continue

            vuln = vulnerabilities[idx]
            vuln["skeptical_score"] = final_score
            vuln["skeptical_reasoning"] = reasoning

            threshold = settings_get_threshold(vuln_type)

            if final_score >= threshold:
                logger.info(
                    f"[{agent_name}] APPROVED #{idx + 1} {vuln_type} "
                    f"(score: {final_score}/10 >= {threshold}): "
                    f"{reasoning[:60]}"
                )
                approved.append(vuln)
            else:
                logger.info(
                    f"[{agent_name}] REJECTED #{idx + 1} {vuln_type} "
                    f"(score: {final_score}/10 < {threshold}): "
                    f"{reasoning[:60]}"
                )
        except Exception as e:
            logger.warning(f"[{agent_name}] Failed to parse finding: {e}")

    logger.info(
        f"[{agent_name}] Skeptical Review: {len(approved)} passed, "
        f"{len(vulnerabilities) - len(approved)} rejected"
    )
    return approved
