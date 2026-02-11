#!/usr/bin/env bash
# ==============================================================================
# BugTraceAI — Anthropic OAuth Setup Wizard
# ==============================================================================
# Authenticates with Claude Pro/Max via OAuth PKCE flow.
# Saves tokens to ~/.bugtrace/auth.json for $0 inference.
# Optionally configures bugtraceaicli.conf to use Anthropic models.
#
# Usage: bash tools/anthropic_login.sh
# ==============================================================================

set -euo pipefail

# ── OAuth Constants ──────────────────────────────────────────────────────────
CLIENT_ID="9d1c250a-e61b-44d9-88ed-5944d1962f5e"
REDIRECT_URI="https://console.anthropic.com/oauth/code/callback"
AUTH_URL="https://claude.ai/oauth/authorize"
TOKEN_URL="https://console.anthropic.com/v1/oauth/token"
SCOPES="org:create_api_key user:profile user:inference"
TOKEN_FILE="$HOME/.bugtrace/auth.json"

# ── Model IDs ────────────────────────────────────────────────────────────────
SONNET_ID="claude-sonnet-4-5-20250929"
HAIKU_ID="claude-haiku-4-5-20251001"
OPUS_ID="claude-opus-4-20250514"

# ── Detect project root (where bugtraceaicli.conf lives) ────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONF_FILE="$PROJECT_ROOT/bugtraceaicli.conf"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
step() { echo -e "\n  ${CYAN}${BOLD}Step $1${NC}  $2"; echo -e "  ${DIM}$(printf '%.0s─' $(seq 1 44))${NC}"; }

# ── Check dependencies ──────────────────────────────────────────────────────
for cmd in openssl curl python3; do
    if ! command -v "$cmd" &>/dev/null; then
        fail "Required command not found: $cmd"
        exit 1
    fi
done

# ==============================================================================
# HEADER
# ==============================================================================

echo ""
echo -e "  ${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "  ${BOLD}║   BugTraceAI — Anthropic OAuth Wizard        ║${NC}"
echo -e "  ${BOLD}║   ${DIM}Claude Pro/Max • \$0 inference${NC}${BOLD}              ║${NC}"
echo -e "  ${BOLD}╚══════════════════════════════════════════════╝${NC}"

# ==============================================================================
# STEP 1: Authenticate
# ==============================================================================

step "1/3" "Authenticate with Anthropic"

VERIFIER=$(openssl rand -base64 32 | tr -d '=\n' | tr '+/' '-_')
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=\n' | tr '+/' '-_')
STATE=$(openssl rand -hex 16)

ENCODED_REDIRECT=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIRECT_URI', safe=''))")
ENCODED_SCOPES=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SCOPES', safe=''))")

FULL_AUTH_URL="${AUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=${ENCODED_REDIRECT}&response_type=code&scope=${ENCODED_SCOPES}&code_challenge=${CHALLENGE}&code_challenge_method=S256&state=${STATE}"

echo ""

# Platform-specific browser open
if command -v xdg-open &>/dev/null; then
    xdg-open "$FULL_AUTH_URL" 2>/dev/null &
elif command -v open &>/dev/null; then
    open "$FULL_AUTH_URL" 2>/dev/null &
elif command -v wslview &>/dev/null; then
    wslview "$FULL_AUTH_URL" 2>/dev/null &
else
    echo -e "  ${YELLOW}Could not open browser. Open this URL manually:${NC}"
    echo "  $FULL_AUTH_URL"
    echo ""
fi

echo -e "  ${BOLD}Paste your Authorization Code:${NC}"
echo -e "  ${DIM}(log in on the browser, copy the full code including the # part)${NC}"
echo ""
read -rp "  Code: " AUTH_CODE

if [ -z "$AUTH_CODE" ]; then
    fail "No code provided."
    exit 1
fi

# Split code#state
CODE=$(echo "$AUTH_CODE" | cut -d'#' -f1)
RESP_STATE=$(echo "$AUTH_CODE" | cut -d'#' -f2)
if [ "$CODE" = "$AUTH_CODE" ]; then
    RESP_STATE=""
fi

echo ""
echo -e "  Exchanging code for tokens..."

TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "code=${CODE}&grant_type=authorization_code&client_id=${CLIENT_ID}&code_verifier=${VERIFIER}&redirect_uri=${REDIRECT_URI}$([ -n "$RESP_STATE" ] && echo "&state=${RESP_STATE}")")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'access_token' in d:
        print(d['access_token'])
    elif 'error' in d:
        print('ERROR:' + d.get('error_description', d['error']))
    else:
        print('ERROR:Unexpected response: ' + json.dumps(d)[:200])
except Exception as e:
    print(f'ERROR:{e}')
")

if [[ "$ACCESS_TOKEN" == ERROR:* ]]; then
    fail "Authentication failed: ${ACCESS_TOKEN#ERROR:}"
    echo ""
    echo -e "  ${DIM}Raw response: $TOKEN_RESPONSE${NC}"
    exit 1
fi

REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))")
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in', 3600))")
EXPIRES_AT=$(python3 -c "import time; print(int((time.time() + $EXPIRES_IN) * 1000))")

# Save tokens
mkdir -p "$HOME/.bugtrace"
cat > "$TOKEN_FILE" << TOKENEOF
{
  "access": "$ACCESS_TOKEN",
  "refresh": "$REFRESH_TOKEN",
  "expires": $EXPIRES_AT
}
TOKENEOF
chmod 600 "$TOKEN_FILE"

ok "Authenticated"

# ==============================================================================
# STEP 2: Test Connection
# ==============================================================================

step "2/3" "Testing connection to Claude"

echo ""
echo -e "  Sending test prompt to Claude...\n"

TEST_PAYLOAD=$(python3 -c "
import json
print(json.dumps({
    'model': '$SONNET_ID',
    'max_tokens': 200,
    'system': 'You are Claude Code, Anthropic\'s official CLI for Claude. Reply only with: I am alive and ready.',
    'messages': [{'role': 'user', 'content': 'Are you alive?'}]
}))
")

TEST_RESPONSE=$(curl -s --max-time 30 "https://api.anthropic.com/v1/messages?beta=true" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -H "anthropic-version: 2023-06-01" \
    -H "anthropic-beta: oauth-2025-04-20,interleaved-thinking-2025-05-14" \
    -H "User-Agent: claude-cli/2.1.2 (external, cli)" \
    -d "$TEST_PAYLOAD")

TEST_TEXT=$(echo "$TEST_RESPONSE" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'content' in d and len(d['content']) > 0:
        for block in d['content']:
            if block.get('type') == 'text':
                print(block['text'])
                sys.exit(0)
        print(d['content'][0].get('text', ''))
    elif 'error' in d:
        print('ERROR:' + d['error'].get('message', str(d['error'])))
    else:
        print('ERROR:Unexpected response: ' + json.dumps(d)[:200])
except Exception as e:
    print(f'ERROR:{e}')
")

if [ -z "$TEST_TEXT" ] || [[ "$TEST_TEXT" == ERROR:* ]]; then
    fail "Connection test failed"
    echo ""
    if [ -n "$TEST_TEXT" ]; then
        echo -e "  ${RED}${TEST_TEXT#ERROR:}${NC}"
    fi
    echo ""
    echo -e "  ${DIM}Raw response:${NC}"
    echo -e "  ${DIM}$TEST_RESPONSE${NC}"
    echo ""
    echo -e "  ${YELLOW}Token was saved but API test failed.${NC}"
    echo "  Try running the wizard again."
    exit 1
fi

echo -e "  Claude says: ${GREEN}\"$TEST_TEXT\"${NC}"
echo ""
ok "Connected"

# ==============================================================================
# STEP 3: Configure BugTraceAI
# ==============================================================================

step "3/3" "Configure BugTraceAI"

echo ""
echo -e "  ${BOLD}Do you want to use Anthropic as your LLM provider in BugTraceAI?${NC}"
echo ""
echo -e "  ${BOLD}1)${NC} ${GREEN}Use Anthropic${NC}  — Switch models to Claude (\$0 on Pro/Max)"
echo -e "  ${BOLD}2)${NC} Keep current   — Don't change anything, just save the token"
echo ""
read -rp "  Choice [1]: " PROVIDER_CHOICE
PROVIDER_CHOICE="${PROVIDER_CHOICE:-1}"

if [[ "$PROVIDER_CHOICE" != "1" ]]; then
    echo ""
    ok "Token saved to $TOKEN_FILE"
    echo ""
    echo -e "  ${DIM}To use Anthropic later, run this wizard again or edit bugtraceaicli.conf:${NC}"
    echo -e "  ${DIM}  [ANTHROPIC] ENABLED = True${NC}"
    echo -e "  ${DIM}  [LLM_MODELS] DEFAULT_MODEL = anthropic/$SONNET_ID${NC}"
    echo ""
    exit 0
fi

# ── .conf file check ────────────────────────────────────────────────────────

if [ ! -f "$CONF_FILE" ]; then
    fail "bugtraceaicli.conf not found at $CONF_FILE"
    echo ""
    echo "  Add this manually to your .conf:"
    echo ""
    echo "  [ANTHROPIC]"
    echo "  ENABLED = True"
    echo ""
    echo "  Then set model names with anthropic/ prefix in [LLM_MODELS]."
    exit 0
fi

# ── Model selection ──────────────────────────────────────────────────────────

echo ""
echo "  Select your Claude model:"
echo ""
echo -e "  ${BOLD}1)${NC} Sonnet 4.5   ${GREEN}(recommended — fast + smart)${NC}"
echo -e "  ${BOLD}2)${NC} Haiku 4.5    (fastest, lowest latency)"
echo -e "  ${BOLD}3)${NC} Opus 4       (most powerful, slowest)"
echo ""
read -rp "  Choice [1]: " MODEL_CHOICE
MODEL_CHOICE="${MODEL_CHOICE:-1}"

case "$MODEL_CHOICE" in
    1) CHOSEN_MODEL="$SONNET_ID" ; CHOSEN_NAME="Sonnet 4.5" ;;
    2) CHOSEN_MODEL="$HAIKU_ID"  ; CHOSEN_NAME="Haiku 4.5" ;;
    3) CHOSEN_MODEL="$OPUS_ID"   ; CHOSEN_NAME="Opus 4" ;;
    *) CHOSEN_MODEL="$SONNET_ID" ; CHOSEN_NAME="Sonnet 4.5" ;;
esac

ANTHROPIC_MODEL="anthropic/$CHOSEN_MODEL"

# ── Backup ───────────────────────────────────────────────────────────────────

cp "$CONF_FILE" "${CONF_FILE}.bak"

# ── Update [ANTHROPIC] section ───────────────────────────────────────────────

echo ""
echo -e "  Configuring bugtraceaicli.conf..."
echo ""

if ! grep -q '^\[ANTHROPIC\]' "$CONF_FILE"; then
    cat >> "$CONF_FILE" << CONFEOF

[ANTHROPIC]
# Direct Anthropic API via OAuth — \$0 on Claude Pro/Max plan.
# Run: bash tools/anthropic_login.sh
ENABLED = True
# TOKEN_FILE = ~/.bugtrace/auth.json
CONFEOF
    ok "[ANTHROPIC] ENABLED = True"
else
    sed -i "s/^ENABLED = False/ENABLED = True/" "$CONF_FILE"
    ok "[ANTHROPIC] ENABLED = True"
fi

# ── Update model fields in [LLM_MODELS] ─────────────────────────────────────

# PRIMARY_MODELS: prepend Anthropic, keep existing as fallback
CURRENT_PRIMARY=$(grep '^PRIMARY_MODELS' "$CONF_FILE" | head -1 | sed 's/PRIMARY_MODELS *= *//')
if [ -n "$CURRENT_PRIMARY" ]; then
    CLEANED_PRIMARY=$(echo "$CURRENT_PRIMARY" | sed 's/anthropic\/[^,]*,\?//g' | sed 's/^,//' | sed 's/,$//')
    if [ -n "$CLEANED_PRIMARY" ]; then
        NEW_PRIMARY="${ANTHROPIC_MODEL},${CLEANED_PRIMARY}"
    else
        NEW_PRIMARY="$ANTHROPIC_MODEL"
    fi
    sed -i "s|^PRIMARY_MODELS = .*|PRIMARY_MODELS = $NEW_PRIMARY|" "$CONF_FILE"
    ok "PRIMARY_MODELS = $NEW_PRIMARY"
fi

# Update individual model fields
for FIELD in DEFAULT_MODEL ANALYSIS_MODEL MUTATION_MODEL CODE_MODEL SKEPTICAL_MODEL REPORTING_MODEL; do
    if grep -q "^${FIELD} = " "$CONF_FILE"; then
        sed -i "s|^${FIELD} = .*|${FIELD} = $ANTHROPIC_MODEL|" "$CONF_FILE"
        ok "${FIELD} = ${ANTHROPIC_MODEL}"
    fi
done

echo ""
echo -e "  ${DIM}VISION_MODEL unchanged (not supported via OAuth)${NC}"
echo -e "  ${DIM}WAF_DETECTION_MODELS unchanged${NC}"
echo -e "  ${DIM}Backup: ${CONF_FILE}.bak${NC}"

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}All done!${NC} BugTraceAI now uses Claude ${CHOSEN_NAME}."
echo ""
echo -e "  Run: ${BOLD}bugtraceai scan https://target.com${NC}"
echo -e "  Revert: ${DIM}cp bugtraceaicli.conf.bak bugtraceaicli.conf${NC}"
echo ""
