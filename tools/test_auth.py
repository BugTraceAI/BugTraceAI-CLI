#!/usr/bin/env python3
"""
Auth Integration Test — BugStore TOTP login.

Tests the full auth pipeline:
1. TOTP code generation (bugtrace/utils/totp.py)
2. Level 2 POST login with TOTP (scan_service._simple_post_login)
3. JWT extraction from response
4. JWT actually grants access to protected endpoints
5. Level 3 browser login (optional, for login_flow based configs)

Usage:
  cd BugTraceAI-CLI
  source .venv/bin/activate
  python tools/test_auth.py

Skeptic criteria (all must pass):
  - TOTP code is valid 6-digit numeric
  - POST login returns HTTP 200
  - JWT is extracted and has 3 parts (valid JWT format)
  - JWT grants access to /api/secure-portal/dashboard (HTTP 200, not 401)
  - Auth config YAML loads and validates correctly
  - scan_service._simple_post_login correctly injects TOTP
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
os.chdir(Path(__file__).parent.parent)

from dotenv import load_dotenv
load_dotenv(".env")

TARGET = "https://bugstore.bugtraceai.com"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
USERNAME = "admin2fa"
PASSWORD = "admin2fa123"

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"

results = []

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((status, name, detail))
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    return condition


print("\n" + "="*65)
print("  BugTraceAI Auth Test — BugStore TOTP (skeptic mode)")
print("="*65)

# ── TEST 1: TOTP code generation ─────────────────────────────────────────────
print("\n[1] TOTP code generation")
from bugtrace.utils.totp import get_totp_code, validate_totp_secret

valid, err = validate_totp_secret(TOTP_SECRET)
check("Secret validates as valid Base32", valid, err or "")

code = get_totp_code(TOTP_SECRET)
check("Code is not None", code is not None, repr(code))
check("Code is 6 digits", code is not None and len(code) == 6, f"got '{code}'")
check("Code is numeric", code is not None and code.isdigit(), f"got '{code}'")

# Generate 3 codes spaced 1s apart — must be same within window
code2 = get_totp_code(TOTP_SECRET)
check("Code is deterministic within window", code == code2, f"{code} vs {code2}")

# ── TEST 2: Raw HTTP login with TOTP ─────────────────────────────────────────
print("\n[2] Raw HTTP POST login with TOTP")
resp = httpx.post(
    f"{TARGET}/api/secure-portal/login",
    json={"username": USERNAME, "password": PASSWORD, "totp_code": code},
    timeout=10
)
check("HTTP 200 on login", resp.status_code == 200, f"got {resp.status_code}")

body = resp.json() if resp.status_code == 200 else {}
check("Response has access_token", "access_token" in body, list(body.keys()))
check("2fa_verified is True", body.get("2fa_verified") is True, str(body.get("2fa_verified")))
jwt = body.get("access_token", "")
check("JWT has 3 parts (valid format)", len(jwt.split(".")) == 3, f"{jwt[:30]}...")

# ── TEST 3: JWT actually grants access ────────────────────────────────────────
print("\n[3] JWT access to protected endpoints")
if jwt:
    headers = {"Authorization": f"Bearer {jwt}"}
    # Test secure-portal /stats — requires 2FA verified JWT
    r = httpx.get(f"{TARGET}/api/secure-portal/stats", headers=headers, timeout=10)
    check("JWT grants access to /secure-portal/stats", r.status_code == 200,
          f"HTTP {r.status_code} body={r.text[:100]}")

    # Test /me endpoint
    r_me = httpx.get(f"{TARGET}/api/secure-portal/me", headers=headers, timeout=10)
    check("JWT grants access to /secure-portal/me", r_me.status_code == 200,
          f"HTTP {r_me.status_code}")

    # Verify /me returns admin2fa identity
    me_data = r_me.json() if r_me.status_code == 200 else {}
    check("Identity confirmed as admin2fa",
          me_data.get("username") == USERNAME or me_data.get("sub") == USERNAME,
          f"got: {me_data.get('username', me_data.get('sub', 'not found'))}")

    # Test that unauthenticated request gets 401/403
    r_unauth = httpx.get(f"{TARGET}/api/secure-portal/stats", timeout=10)
    check("Unauthenticated request to /stats is blocked (401/403)",
          r_unauth.status_code in (401, 403),
          f"HTTP {r_unauth.status_code}")

    # Test wrong TOTP fails
    r_bad = httpx.post(
        f"{TARGET}/api/secure-portal/login",
        json={"username": USERNAME, "password": PASSWORD, "totp_code": "000000"},
        timeout=10
    )
    check("Wrong TOTP code is rejected (401)", r_bad.status_code == 401,
          f"HTTP {r_bad.status_code}")
else:
    check("JWT grants access (skipped — no JWT)", False, "login failed")

# ── TEST 4: Auth config YAML loading ─────────────────────────────────────────
print("\n[4] Auth config YAML loading")
from bugtrace.utils.auth_config import load_auth_config

yaml_content = f"""
authentication:
  login_type: api
  login_url: "{TARGET}/api/secure-portal/login"
  credentials:
    username: "{USERNAME}"
    password: "{PASSWORD}"
    totp_secret: "{TOTP_SECRET}"
  success_condition:
    type: url_contains
    value: "/dashboard"
"""

# Write temp file
tmp = Path("/tmp/test_auth_bugstore.yaml")
tmp.write_text(yaml_content)

cfg, err = load_auth_config(str(tmp))
check("YAML config loads without error", cfg is not None, err or "")
if cfg:
    check("login_url preserved", cfg.get("login_url") == f"{TARGET}/api/secure-portal/login",
          cfg.get("login_url"))
    check("username preserved", cfg.get("credentials", {}).get("username") == USERNAME,
          cfg.get("credentials", {}).get("username"))
    check("totp_secret preserved", cfg.get("credentials", {}).get("totp_secret") == TOTP_SECRET,
          cfg.get("credentials", {}).get("totp_secret"))

tmp.unlink()

# ── TEST 5: scan_service._simple_post_login behavior ────────────────────────
print("\n[5] scan_service._simple_post_login with TOTP")

async def test_scan_service_auth():
    from bugtrace.services.scan_service import ScanService
    from unittest.mock import MagicMock, AsyncMock, patch

    service = ScanService.__new__(ScanService)

    stored = {}
    def mock_store(scan_ctx_id, source, token=None, cookies=None):
        stored["token"] = token
        stored["cookies"] = cookies
        stored["source"] = source

    credentials = {
        "username": USERNAME,
        "password": PASSWORD,
        "totp_secret": TOTP_SECRET,
    }

    with patch("bugtrace.services.scan_context.store_auth_token", side_effect=mock_store):
        await service._simple_post_login(
            "test_ctx_001",
            f"{TARGET}/api/secure-portal/login",
            credentials
        )

    check("_simple_post_login stored a token", stored.get("token") is not None,
          f"source={stored.get('source')}, token={str(stored.get('token', ''))[:40]}...")
    if stored.get("token"):
        token = stored["token"]
        check("Stored token is valid JWT", len(token.split(".")) == 3,
              f"{token[:30]}...")
    return stored

stored = asyncio.run(test_scan_service_auth())

# ── TEST 6: TOTP field name detection (totp_code vs totp vs code) ─────────────
print("\n[6] TOTP field name robustness")
# Test that wrong field name gives 422/400 (API is strict)
r_wrong_field = httpx.post(
    f"{TARGET}/api/secure-portal/login",
    json={"username": USERNAME, "password": PASSWORD, "totp": code},
    timeout=10
)
check("API rejects wrong TOTP field name (422)",
      r_wrong_field.status_code in (400, 422),
      f"HTTP {r_wrong_field.status_code} — API needs 'totp_code' specifically")

# Verify correct field name works
new_code = get_totp_code(TOTP_SECRET)
r_correct = httpx.post(
    f"{TARGET}/api/secure-portal/login",
    json={"username": USERNAME, "password": PASSWORD, "totp_code": new_code},
    timeout=10
)
check("Correct field 'totp_code' accepted (200)", r_correct.status_code == 200,
      f"HTTP {r_correct.status_code}")

# ── SUMMARY ───────────────────────────────────────────────────────────────────
print("\n" + "="*65)
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
warned = sum(1 for s, _, _ in results if s == WARN)
total = len(results)

print(f"  RESULT: {passed}/{total} passed, {failed} failed, {warned} warnings")

if failed > 0:
    print("\n  FAILED TESTS:")
    for s, name, detail in results:
        if s == FAIL:
            print(f"    {s} {name}: {detail}")

verdict = "✅ ALL TESTS PASSED" if failed == 0 else f"❌ {failed} TEST(S) FAILED — NOT READY"
print(f"\n  {verdict}")
print("="*65 + "\n")

sys.exit(0 if failed == 0 else 1)
