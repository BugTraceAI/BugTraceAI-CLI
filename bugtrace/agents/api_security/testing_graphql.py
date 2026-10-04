"""
API Security Agent — I/O functions.

All functions in this module perform HTTP I/O. Dependencies (httpx clients,
endpoints) are passed as explicit parameters.

Contents:
    - test_graphql_introspection: Test if GraphQL introspection is enabled
    - test_graphql_injection: Test for injection in GraphQL queries
    - test_graphql_dos: Test for nested query DoS
    - test_graphql_endpoint: Comprehensive GraphQL security testing
    - test_auth_bypass: Test authentication bypass techniques
    - test_idor: Test for Insecure Direct Object Reference
    - test_http_verb_tampering: Test HTTP method override vulnerabilities
    - test_rest_endpoint: Comprehensive REST API testing
    - test_websocket: Test WebSocket security
    - discover_graphql_endpoint: Discover GraphQL endpoint from base URL
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from loguru import logger

import httpx

from bugtrace.agents.api_security.core import (
    WEBSOCKETS_AVAILABLE,
    parse_introspection_response,
    is_graphql_validation_error,
    check_injection_response,
    check_bypass_response,
    check_idor_response,
    check_verb_tampering,
    create_introspection_vuln,
    create_injection_vuln,
    create_idor_finding,
)


# ==================== GRAPHQL TESTING ====================


# ==================== GRAPHQL TESTING ====================

async def test_graphql_introspection(endpoint: str) -> Dict:  # I/O
    """Test if GraphQL introspection is enabled.

    Args:
        endpoint: The GraphQL endpoint URL.

    Returns:
        Dict with 'enabled' flag and optional 'schema'/'type_count'.
    """
    introspection_query = {
        "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                        }
                    }
                }
            }
        """
    }

    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.post(
                endpoint,
                json=introspection_query,
                headers={"Content-Type": "application/json"},
            )
            data = response.json()
            return parse_introspection_response(response.status_code, data)
    except Exception as e:
        logger.warning(f"GraphQL introspection test failed: {e}")
        return {"enabled": False}


async def _test_single_injection(endpoint: str, payload: Dict, baseline_text: str = "") -> Dict:  # I/O
    """Test a single GraphQL injection payload.

    Args:
        endpoint: The GraphQL endpoint URL.
        payload: The injection payload variables.
        baseline_text: Response text from the same query with a benign value, so a DB
            error signature only counts when it is NOT already present in the baseline.

    Returns:
        Dict with 'vulnerable' flag.
    """
    query = {
        "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
        "variables": payload,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(endpoint, json=query)
            return check_injection_response(response.text, payload, baseline_text)
    except Exception as e:
        logger.debug(f"operation failed: {e}")
        return {"vulnerable": False}


async def test_graphql_injection(endpoint: str) -> Dict:  # I/O
    """Test for injection vulnerabilities in GraphQL queries.

    Args:
        endpoint: The GraphQL endpoint URL.

    Returns:
        Dict with 'vulnerable' flag and optional payload/response.
    """
    injection_payloads = [
        {"id": "1' OR '1'='1"},
        {"id": "1; DROP TABLE users--"},
        {"search": "test' UNION SELECT password FROM users--"},
        {"user": {"id": "1", "role": "admin"}},
    ]

    # Baseline: same query with a benign value. A DB-error signature only counts as
    # injection when it is ABSENT here — otherwise a schema mismatch or an app that
    # always surfaces an error would false-positive on every payload.
    baseline_text = ""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            base_resp = await client.post(endpoint, json={
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
                "variables": {"id": "1"},
            })
            baseline_text = base_resp.text
    except Exception as e:
        logger.debug(f"injection baseline failed: {e}")

    for payload in injection_payloads:
        result = await _test_single_injection(endpoint, payload, baseline_text)
        if result.get("vulnerable"):
            return result

    return {"vulnerable": False}


async def test_graphql_dos(endpoint: str) -> Dict:  # I/O
    """Test for Nested Query DoS vulnerability.

    STRICT: a 500 or a slow response ALONE is not DoS — a nested probe against fields
    that do not exist is rejected cheaply (often 500), which is a schema mismatch, not
    amplification. We time a trivial baseline query, then only flag when the nested query
    is BOTH slow in absolute terms AND dramatically slower than baseline AND was actually
    processed (not a GraphQL validation error).

    Args:
        endpoint: The GraphQL endpoint URL.

    Returns:
        Dict with 'vulnerable' flag and optional 'duration'/'baseline'.
    """
    simple_query = {"query": "{ __typename }"}
    nested_query = {
        "query": """
            query {
                user {
                    posts {
                        author {
                            posts {
                                author {
                                    posts {
                                        comments {
                                            author { name }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        """
    }

    baseline = 0.2
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            # Baseline: time a trivial query so we can compare against the nested one.
            try:
                t0 = time.time()
                await client.post(endpoint, json=simple_query, timeout=10)
                baseline = max(0.05, time.time() - t0)
            except Exception:
                pass

            # Nested query timing.
            try:
                t1 = time.time()
                response = await client.post(endpoint, json=nested_query, timeout=20)
                duration = time.time() - t1
            except (httpx.TimeoutException, asyncio.TimeoutError):
                return {"vulnerable": True, "duration": 20.0, "baseline": baseline,
                        "note": "nested query exceeded 20s timeout"}

            # A validation error (unknown fields) is a cheap rejection, not DoS — even at 500.
            try:
                data = response.json()
            except Exception:
                data = None
            if is_graphql_validation_error(response.status_code, data):
                return {"vulnerable": False}

            # Real amplification: slow in absolute terms AND >>10x the baseline.
            if duration > 5.0 and duration > baseline * 10:
                return {"vulnerable": True, "duration": duration, "baseline": baseline}
    except Exception as e:
        logger.debug(f"operation failed: {e}")

    return {"vulnerable": False}


async def test_graphql_endpoint(
    endpoint: str,
    log_fn: Any = None,
) -> Dict[str, Any]:  # I/O
    """Comprehensive GraphQL security testing.

    Args:
        endpoint: The GraphQL endpoint URL.
        log_fn: Optional callable(message, level) for logging.

    Returns:
        Dict with 'endpoint' and 'vulnerabilities' list.
    """
    if log_fn:
        log_fn(f"GraphQL Testing: {endpoint}", "INFO")

    results: Dict[str, Any] = {"endpoint": endpoint, "vulnerabilities": []}

    # Test 1: Introspection
    introspection_result = await test_graphql_introspection(endpoint)
    if introspection_result["enabled"]:
        results["vulnerabilities"].append(create_introspection_vuln(introspection_result))

    # Test 2: Injection in queries
    injection_result = await test_graphql_injection(endpoint)
    if injection_result["vulnerable"]:
        results["vulnerabilities"].append(create_injection_vuln(injection_result, endpoint))

    # Test 3: Nested query DoS
    dos_result = await test_graphql_dos(endpoint)
    if dos_result["vulnerable"]:
        _dur = dos_result.get("duration")
        _base = dos_result.get("baseline")
        results["vulnerabilities"].append({
            "type": "GraphQL Nested Query DoS",
            "severity": "HIGH",
            "duration": _dur,
            "baseline": _base,
            "description": (
                f"Deeply nested query took {_dur}s vs a {_base}s baseline "
                f"({dos_result.get('note', 'no depth/complexity limit enforced')}) — "
                f"the server accepts unbounded query depth."
            ),
        })

    # Test 4: Schema-driven unauthenticated read exposure
    if introspection_result["enabled"]:
        read_result = await test_graphql_unauth_read_exposure(endpoint)
        if read_result.get("vulnerabilities"):
            results["vulnerabilities"].extend(read_result["vulnerabilities"])

        # Test 5: Reversible write authorization (gated on readable records)
        write_result = await test_graphql_unauth_write_authz(endpoint)
        if write_result.get("vulnerabilities"):
            results["vulnerabilities"].extend(write_result["vulnerabilities"])

    return results


# ==================== SCHEMA-DRIVEN GRAPHQL READ EXPOSURE ====================

_FULL_INTROSPECTION_QUERY = {
    "query": """
        query FullIntrospection {
            __schema {
                queryType { name fields { name args { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } } type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } } }
                mutationType { name fields { name args { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } } type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } } }
                types {
                    name kind
                    fields { name args { name type { name kind ofType { name kind ofType { name kind } } } } type { name kind ofType { name kind ofType { name kind } } } }
                    inputFields { name type { name kind ofType { name kind } } }
                }
            }
        }
    """
}


_SENSITIVE_FIELD_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(^|_)id\b(?![^a-zA-Z])", r"(^|_)user", r"(^|_)email", r"(^|_)passw", r"(^|_)token",
        r"(^|_)secret", r"(^|_)key\b", r"(^|_)role", r"(^|_)permis", r"(^|_)admin",
        r"(^|_)credential", r"(^|_)auth", r"(^|_)session", r"(^|_)phone",
        r"(^|_)address", r"(^|_)ssn", r"(^|_)credit", r"(^|_)card", r"(^|_)bank",
        r"(^|_)salary", r"(^|_)pii\b", r"(^|_)privat", r"(^|_)personal",
        r"\b(first_?name|last_?name|username|full_?name|display_?name|nickname)\b",
        r"\bprofile\b", r"\baccount\b", r"\bbalance\b",
    ]
]

assert _SENSITIVE_FIELD_PATTERNS  # pyflakes silence


def _resolve_ofType_simple(type_ref) -> str:
    """Walk ofType chain to find the innermost named type."""
    if not isinstance(type_ref, dict):
        return ""
    name = type_ref.get("name")
    if name:
        return name
    inner = type_ref.get("ofType")
    if inner:
        return _resolve_ofType_simple(inner)
    return ""


def _is_scalar_type(type_name: str) -> bool:
    return type_name.upper() in {"ID", "STRING", "INT", "FLOAT", "BOOLEAN", "INTEGER"}


def _is_enum_type(type_name: str, enum_names: set) -> bool:
    return type_name in enum_names


def _is_sensitive_field(field_name: str) -> bool:
    return any(p.search(field_name) for p in _SENSITIVE_FIELD_PATTERNS)


def _is_required_arg(arg_info: dict) -> bool:
    """Check if an argument is NON_NULL (required)."""
    tt = arg_info.get("type", {})
    if isinstance(tt, dict) and tt.get("kind") == "NON_NULL":
        return True
    return False


def _parse_full_introspection(schema_data: dict) -> dict:
    """Parse full introspection result into a structured type graph."""
    schema = schema_data.get("__schema", {}) if isinstance(schema_data, dict) else {}
    query_type_name = schema.get("queryType", {}).get("name", "Query")
    mutation_type_name = schema.get("mutationType", {})
    if mutation_type_name:
        mutation_type_name = mutation_type_name.get("name", None)

    types = schema.get("types", [])
    type_map = {}
    enum_names = set()

    for t in types:
        name = t.get("name", "")
        kind = t.get("kind", "")
        if kind == "ENUM":
            enum_names.add(name)
        fields = t.get("fields") or []
        field_list = []
        for f in fields:
            fname = f.get("name", "")
            field_type_name = _resolve_ofType_simple(f.get("type"))
            args = f.get("args") or []
            arg_list = []
            for a in args:
                aname = a.get("name", "")
                atype_name = _resolve_ofType_simple(a.get("type"))
                atype_info = a.get("type", {})
                required = atype_info.get("kind") == "NON_NULL" if isinstance(atype_info, dict) else False
                arg_list.append({
                    "name": aname, "type_name": atype_name,
                    "required": required, "type_kind": atype_info.get("kind", ""),
                })
            field_list.append({
                "name": fname, "type_name": field_type_name,
                "args": arg_list,
            })
        type_map[name] = {"kind": kind, "fields": field_list}

    query_fields = []
    if query_type_name in type_map:
        query_fields = type_map[query_type_name].get("fields", [])

    mutation_fields = []
    if mutation_type_name and mutation_type_name in type_map:
        mutation_fields = type_map[mutation_type_name].get("fields", [])

    return {
        "query_fields": query_fields,
        "mutation_fields": mutation_fields,
        "type_map": type_map,
        "enum_names": enum_names,
        "query_type_name": query_type_name,
        "mutation_type_name": mutation_type_name,
    }


def _build_safe_selection_set(type_name: str, type_map: dict, enum_names: set, depth: int = 0, max_depth: int = 2, max_fields: int = 10) -> List[str]:
    """Build a safe, shallow selection set of scalar/enum fields for a type."""
    if depth > max_depth:
        return []

    info = type_map.get(type_name)
    if not info:
        return []

    fields = info.get("fields", [])
    selected = []
    for f in fields:
        ftype_name = f.get("type_name", "")
        if _is_scalar_type(ftype_name):
            selected.append(f["name"])
        elif _is_enum_type(ftype_name, enum_names):
            selected.append(f["name"])
        elif ftype_name and type_map.get(ftype_name):
            if depth < max_depth and len(selected) < max_fields:
                nested = _build_safe_selection_set(ftype_name, type_map, enum_names, depth + 1, max_depth, max_fields)
                if nested:
                    selected.append(f"{f['name']} {{ {' '.join(nested[:4])} }}")

    return selected[:max_fields]


def _classify_read_exposure(field_name: str, returned_fields: List[str], returned_count: int) -> dict:
    """Classify whether a GraphQL read result exposes sensitive data."""
    if returned_count == 0:
        return {"is_sensitive": False, "reason": "No records returned", "fields": []}

    has_sensitive = any(_is_sensitive_field(f) for f in returned_fields)
    has_identity = any(
        re.search(r, f or "", re.IGNORECASE)
        for r in [r"(^|_)user", r"(^|_)email", r"(^|_)username", r"(^|_)first_?name", r"(^|_)last_?name"]
        for f in returned_fields
    )
    has_role_perm = any(
        re.search(r, f or "", re.IGNORECASE)
        for r in [r"role", r"permi", r"admin", r"is_"]
        for f in returned_fields
    )

    sensitive_count = sum(1 for f in returned_fields if _is_sensitive_field(f))
    if sensitive_count < 2 and not has_identity and not has_role_perm:
        return {
            "is_sensitive": False,
            "reason": "Insufficient security-relevant fields (need ≥2 or identity/role)",
            "fields": returned_fields[:20],
        }

    if has_identity:
        return {
            "is_sensitive": True,
            "classification": "Unauthenticated identity/personal data exposure",
            "fields": returned_fields[:20],
        }

    if has_sensitive or has_role_perm:
        return {
            "is_sensitive": True,
            "classification": "Unauthenticated sensitive data exposure",
            "fields": returned_fields[:20],
        }

    return {
        "is_sensitive": False,
        "reason": "Response received but no security-relevant fields identified",
        "fields": returned_fields[:20],
    }


async def _do_graphql_query(endpoint: str, query_parts: List[str], query_type: str, field_name: str, args_str: str = "") -> tuple:
    """Execute a GraphQL query and return (data_dict, response_text)."""
    full_query = f"query {{ {field_name}{args_str} {{ {' '.join(query_parts)} }} }}"
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                endpoint,
                json={"query": full_query},
                headers={"Content-Type": "application/json"},
            )
            text = resp.text
            try:
                data = resp.json()
            except Exception:
                data = None
            return data, text, resp.status_code
    except Exception as e:
        return None, str(e), 0


async def _do_graphql_mutation(endpoint: str, mutation_name: str, args: dict, selection: str) -> tuple:
    """Execute a GraphQL mutation and return (data_dict, response_text, status)."""
    args_str = ", ".join(f"{k}: {json.dumps(v)}" for k, v in args.items())
    full_query = f"mutation {{ {mutation_name}({args_str}) {{ {selection} }} }}"
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                endpoint,
                json={"query": full_query},
                headers={"Content-Type": "application/json"},
            )
            text = resp.text
            try:
                data = resp.json()
            except Exception:
                data = None
            return data, text, resp.status_code
    except Exception as e:
        return None, str(e), 0


async def test_graphql_unauth_read_exposure(endpoint: str) -> Dict:
    """Schema-driven unauthenticated GraphQL read exposure check.

    Performs full introspection, identifies root query fields requiring no
    arguments, builds safe shallow scalar-only selection sets, sends
    unauthenticated queries, and classifies responses for security-relevant
    data exposure (identity, contact, role/permission, etc.).

    Returns:
        Dict with 'vulnerabilities' list.
    """
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as client:
            resp = await client.post(
                endpoint,
                json=_FULL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                return {"vulnerabilities": []}
            raw = resp.json()
    except Exception as e:
        logger.debug(f"Full introspection failed: {e}")
        return {"vulnerabilities": []}

    schema_data = raw.get("data", {})
    if not schema_data:
        return {"vulnerabilities": []}

    parsed = _parse_full_introspection(schema_data)
    query_fields = parsed["query_fields"]
    type_map = parsed["type_map"]
    enum_names = parsed["enum_names"]

    if not query_fields:
        return {"vulnerabilities": []}

    vulns = []
    tested_count = 0

    for qf in query_fields:
        args = qf.get("args", [])
        required_args = [a for a in args if a.get("required")]
        if required_args:
            continue

        field_name = qf["name"]
        return_type = qf.get("type_name", "")
        selection = _build_safe_selection_set(return_type, type_map, enum_names, max_depth=2, max_fields=10)
        if not selection:
            selection = ["__typename"]

        data, text, status = await _do_graphql_query(endpoint, selection, "query", field_name)
        tested_count += 1

        if not data or status != 200:
            continue

        result_data = data.get("data", {}).get(field_name)
        if result_data is None:
            continue

        if isinstance(result_data, list):
            returned_fields = list(result_data[0].keys()) if result_data and isinstance(result_data[0], dict) else []
            returned_count = len(result_data)
        elif isinstance(result_data, dict):
            returned_fields = list(result_data.keys())
            returned_count = 1
        else:
            continue

        classification = _classify_read_exposure(field_name, returned_fields, returned_count)
        if classification.get("is_sensitive"):
            vulns.append({
                "type": "GraphQL Unauthenticated Data Exposure",
                "severity": "HIGH",
                "url": endpoint,
                "parameter": "query",
                "field": field_name,
                "exposed_fields": classification.get("fields", []),
                "record_count": returned_count,
                "classification": classification.get("classification", ""),
                "query_used": f"query {{ {field_name} {{ {' '.join(selection[:6])} }} }}",
                "description": (
                    f"Unauthenticated GraphQL query `{field_name}` returns "
                    f"{returned_count} record(s) with sensitive fields: "
                    f"{', '.join(classification.get('fields', [])[:10])}. "
                    f"Classification: {classification.get('classification')}"
                ),
            })
            logger.info(
                f"GraphQL unauthenticated exposure: {field_name} -> "
                f"{returned_count} records, fields={classification.get('fields', [])[:5]}"
            )

        if tested_count >= 8:
            break

    return {"vulnerabilities": vulns}


# ==================== SCHEMA-DRIVEN GRAPHQL WRITE AUTHORIZATION ====================

_REVERSIBLE_MUTATION_TEXT_FIELDS = ["bio", "about", "description", "status", "note", "title", "display_name"]


def _resolvable_introspection(info, endpoint: str) -> Optional[dict]:
    """Check if full introspection data is available and resolvable."""
    if not info or not info.get("mutation_type_name"):
        return None
    return info


def _find_reversible_mutations(parsed_schema: dict) -> List[dict]:
    """Find mutations that have a reversible text-like field and an object identifier.

    Returns list of dicts with {name, id_arg, text_arg, return_type, id_type}.
    """
    mutation_fields = parsed_schema.get("mutation_fields", [])
    type_map = parsed_schema.get("type_map", {})

    candidates = []
    dangerous_keywords = ["delete", "remove", "reset", "changePassword", "setPassword",
                          "changeEmail", "setEmail", "transfer", "purchase", "pay"]

    for mf in mutation_fields:
        name = mf.get("name", "")
        low_name = name.lower()

        skip = False
        for kw in dangerous_keywords:
            if kw.lower() in low_name:
                skip = True
                break
        if skip:
            continue

        args = mf.get("args", [])
        id_arg = None
        text_arg = None
        for a in args:
            aname = a.get("name", "")
            atypename = a.get("type_name", "")
            if aname in ("id", "userId", "user_id", "objectId", "itemId"):
                id_arg = a
            if atypename == "String" and aname not in ("id", "userId", "user_id", "objectId", "itemId"):
                if text_arg is None or aname.lower() in _REVERSIBLE_MUTATION_TEXT_FIELDS:
                    text_arg = a

        if id_arg and text_arg:
            candidates.append({
                "name": name,
                "id_arg_name": id_arg["name"],
                "text_arg_name": text_arg["name"],
                "return_type": mf.get("type_name", ""),
            })

    return candidates


async def test_graphql_unauth_write_authz(
    endpoint: str,
    parsed_schema: Optional[dict] = None,
) -> Dict:
    """Reversible GraphQL write authorization check.

    Performs full introspection, identifies mutations with reversible text-like
    fields and object identifiers, then tests write authorization via a
    read→mutate→verify→restore→verify cycle.

    Safety gates:
    - Only reversible text-like fields (bio, about, description, etc.)
    - Only mutations where an ID and text field can be resolved from schema
    - Original value is read first, then restored in a `finally` block
    - Restore is verified — critical warning emitted on failure
    - Delete/password/email/role/money operations are skipped

    Returns:
        Dict with 'vulnerabilities' list.
    """
    if parsed_schema is None:
        try:
            async with httpx.AsyncClient(timeout=20, verify=False) as client:
                resp = await client.post(
                    endpoint,
                    json=_FULL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code != 200:
                    return {"vulnerabilities": []}
                raw = resp.json()
        except Exception as e:
            logger.debug(f"Mutation introspection failed: {e}")
            return {"vulnerabilities": []}

        schema_data = raw.get("data", {})
        if not schema_data:
            return {"vulnerabilities": []}
        parsed_schema = _parse_full_introspection(schema_data)

    if not parsed_schema:
        return {"vulnerabilities": []}

    candidates = _find_reversible_mutations(parsed_schema)
    if not candidates:
        return {"vulnerabilities": []}

    vulns = []
    type_map = parsed_schema["type_map"]
    abort_mutation_testing = False

    for candidate in candidates[:3]:
        if abort_mutation_testing:
            break
        mutation_name = candidate["name"]
        id_arg_name = candidate["id_arg_name"]
        text_arg_name = candidate["text_arg_name"]
        return_type_name = candidate["return_type"]

        sel_fields = _build_safe_selection_set(return_type_name, type_map, parsed_schema.get("enum_names", set()), max_depth=1, max_fields=5)
        if not sel_fields:
            sel_fields = ["__typename"]
        selection = " ".join(sel_fields[:3])

        id_val = None
        orig_text = ""
        benign_marker = ""
        mutated = False
        exploit_verified = False
        restore_verified = False

        try:
            original = await _read_current_value(endpoint, mutation_name, id_arg_name, text_arg_name, selection, type_map, parsed_schema.get("enum_names", set()))
            if not original or original.get("id_value") is None:
                continue

            id_val = original["id_value"]
            orig_text = original["text_value"] or ""
            benign_marker = "bugtrace_validation_" + str(int(time.time()))[-6:]

            set_ok = await _try_set_value(endpoint, mutation_name, id_arg_name, id_val, text_arg_name, benign_marker, selection)
            if not set_ok:
                continue
            mutated = True

            exploit_verified = await _verify_value(endpoint, mutation_name, id_arg_name, id_val, text_arg_name, benign_marker, selection, type_map, parsed_schema.get("enum_names", set()))
            if not exploit_verified:
                continue
        except Exception as e:
            logger.warning(f"Error testing mutation {mutation_name}: {e}")
        finally:
            if mutated and id_val is not None and orig_text is not None:
                try:
                    restore_ok = await _try_set_value(
                        endpoint, mutation_name, id_arg_name, id_val,
                        text_arg_name, orig_text, selection,
                    )
                    if restore_ok:
                        restore_verified = await _verify_value(
                            endpoint, mutation_name, id_arg_name, id_val,
                            text_arg_name, orig_text, selection, type_map,
                            parsed_schema.get("enum_names", set()),
                        )
                    if not restore_ok or not restore_verified:
                        logger.critical(
                            f"GraphQL mutation restore FAILED for {mutation_name} on {endpoint}! "
                            f"Record {id_val} may still carry the marker."
                        )
                        abort_mutation_testing = True
                except Exception as e:
                    logger.critical(
                        f"finally: could NOT restore {mutation_name} on {endpoint}! "
                        f"Record {id_val} may still carry the marker. Error: {e}"
                    )
                    abort_mutation_testing = True

        if exploit_verified and restore_verified:
            vulns.append({
                "type": "GraphQL Unauthenticated Mutation",
                "severity": "CRITICAL",
                "url": endpoint,
                "parameter": "query",
                "mutation": mutation_name,
                "id_arg": id_arg_name,
                "text_arg": text_arg_name,
                "id_value": id_val,
                "original_value": orig_text[:100] if orig_text else "(empty)",
                "marker_value": benign_marker,
                "restored": True,
                "description": (
                    f"Unauthenticated GraphQL mutation `{mutation_name}` allows "
                    f"modifying record {id_val} via the `{text_arg_name}` field. "
                    f"Original value '{orig_text[:80]}' was replaced with marker "
                    f"'{benign_marker}', confirmed, and restored (verified). "
                    f"This is a confirmed IDOR/BAC on GraphQL write operations."
                ),
            })

    return {"vulnerabilities": vulns}


async def _read_current_value(
    endpoint: str, mutation_name: str, id_arg_name: str,
    text_arg_name: str, selection: str, type_map: dict, enum_names: set,
    target_id=None,
) -> Optional[dict]:
    """Read the current value of a reversible field via a query, using the mutation's ID.

    Attempts to find a matching query field (e.g. `user(id: 1)`) using common patterns.
    Returns {'id_value': any, 'text_value': str} or None.
    """
    query_type = type_map.get("Query", type_map.get("RootQueryType", {}))
    query_fields = query_type.get("fields", []) if isinstance(query_type, dict) else type_map.get("type_map", {}).get("Query", {}).get("fields", [])

    test_ids = [target_id] if target_id is not None else [1, 2, 3]
    for test_id in test_ids:
        for qf in query_fields[:6]:
            qname = qf.get("name", "")
            qargs = qf.get("args", [])
            has_id = any(
                a.get("name") in (id_arg_name, "id") and a.get("type_name", "").upper() in ("ID", "INT")
                for a in qargs
            )
            if not has_id:
                continue

            matching_id_arg = next(
                (a for a in qargs if a.get("name") in (id_arg_name, "id") and a.get("type_name", "").upper() in ("ID", "INT")),
                None,
            )
            arg_name = matching_id_arg["name"] if matching_id_arg else "id"
            if matching_id_arg["type_name"].upper() == "INT":
                arg_val = str(test_id)
            else:
                arg_val = json.dumps(str(test_id))
            args_str = f'({arg_name}: {arg_val})'

            safe_sel = _build_safe_selection_set(qf.get("type_name", ""), type_map, enum_names, max_depth=1, max_fields=5)
            if not safe_sel:
                safe_sel = [text_arg_name, "__typename"]
            if text_arg_name not in safe_sel:
                safe_sel.insert(0, text_arg_name)

            data, _, status = await _do_graphql_query(endpoint, safe_sel, "query", qname, args_str)
            if not data or status != 200:
                continue

            result_data = data.get("data", {}).get(qname)
            if isinstance(result_data, list) and result_data and isinstance(result_data[0], dict):
                item = result_data[0]
                id_val = item.get(id_arg_name) or item.get("id")
                if id_val is None or text_arg_name not in item:
                    continue
                if target_id is not None and str(id_val) != str(target_id):
                    continue
                text_val = item.get(text_arg_name)
                if text_val is None:
                    continue
                return {"id_value": id_val, "text_value": str(text_val)}
            elif isinstance(result_data, dict):
                id_val = result_data.get(id_arg_name) or result_data.get("id")
                if id_val is None or text_arg_name not in result_data:
                    continue
                if target_id is not None and str(id_val) != str(target_id):
                    continue
                text_val = result_data.get(text_arg_name)
                if text_val is None:
                    continue
                return {"id_value": id_val, "text_value": str(text_val)}

    return None


async def _try_set_value(
    endpoint: str, mutation_name: str, id_arg_name: str,
    id_val, text_arg_name: str, new_value: str, selection: str,
) -> bool:
    """Try to set a text field value via a GraphQL mutation. Returns True on success."""
    args = {id_arg_name: id_val, text_arg_name: new_value}
    data, text, status = await _do_graphql_mutation(endpoint, mutation_name, args, selection)
    if not data or status != 200:
        return False
    result = data.get("data", {}).get(mutation_name)
    if result is None and "errors" in data:
        return False
    return True


async def _verify_value(
    endpoint: str, mutation_name: str, id_arg_name: str,
    id_val, text_arg_name: str, expected_value: str, selection: str,
    type_map: dict, enum_names: set,
) -> bool:
    """Verify that a field has the expected value by reading it back."""
    current = await _read_current_value(
        endpoint, mutation_name, id_arg_name, text_arg_name, selection,
        type_map, enum_names, target_id=id_val,
    )
    if not current:
        return False
    return str(current.get("text_value", "")) == str(expected_value)


# ==================== REST API TESTING ====================


