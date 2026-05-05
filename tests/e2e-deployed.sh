#!/usr/bin/env bash
# tests/e2e-deployed.sh - E2E test harness for a live deployed stack.
#
# Runs HTTP control-plane assertions against a Pulumi-provisioned staging or
# production stack. Unlike compose-test.sh (which uses hardcoded Docker Compose
# IPs on port 80/81), this script targets real EC2 public IPs on the production
# SG ports: 8090 (public) and 8091 (admin, admin_cidr only).
#
# Usage:
#   # Env vars already exported (e.g. from make e2e-deployed):
#   bash tests/e2e-deployed.sh
#
#   # Or: let the script call stack_outputs.py itself:
#   STACK=staging bash tests/e2e-deployed.sh
#
# Required env vars (set manually or via stack_outputs.py --format env):
#   BACKEND_HOST         - backend EC2 public IP
#   BACKEND_PORT         - public HTTP port (default: 8090)
#   ADMIN_BACKEND_PORT   - admin HTTP port (default: 8091)
#   RELAY_IDS            - space-separated relay node names from Pulumi output
#                          e.g. "relay-staging-1 relay-staging-2 relay-staging-3"
#
# On failure: script exits non-zero. The stack is intentionally left alive for
# forensic inspection. Run `make e2e-teardown STACK=<stack>` when done.
#
# Prerequisites:
#   - curl
#   - nc (netcat) for TCP preflight
#   - python3 + pulumi CLI (only when STACK is set and env vars are absent)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

# ---------------------------------------------------------------------------
# Resolve env vars from stack_outputs.py if not already set
# ---------------------------------------------------------------------------
if [ -z "${BACKEND_HOST:-}" ]; then
    STACK="${STACK:-staging}"
    echo -e "${YELLOW}=== Resolving stack outputs for: ${STACK} ===${NC}"
    eval "$(python3 "${ROOT_DIR}/infra/stack_outputs.py" --stack "${STACK}" --format env)"
    echo "  BACKEND_HOST=${BACKEND_HOST}"
    echo "  RELAY_IDS=${RELAY_IDS}"
    echo ""
fi

# Apply defaults for optional vars.
BACKEND_PORT="${BACKEND_PORT:-8090}"
ADMIN_BACKEND_PORT="${ADMIN_BACKEND_PORT:-8091}"

BACKEND_URL="http://${BACKEND_HOST}:${BACKEND_PORT}"
ADMIN_BACKEND_URL="http://${BACKEND_HOST}:${ADMIN_BACKEND_PORT}"

# Derive relay count from RELAY_IDS for dynamic assertions.
RELAY_COUNT=0
for _id in ${RELAY_IDS:-}; do
    RELAY_COUNT=$((RELAY_COUNT + 1))
done

# ---------------------------------------------------------------------------
# TCP preflight - fail fast before waiting 60s if admin port is blocked.
# The admin port 8091 is restricted to admin_cidr in the SG. If the test
# runner's IP is not in admin_cidr the connection will be refused immediately.
# ---------------------------------------------------------------------------
echo -e "${YELLOW}=== TCP preflight: ${BACKEND_HOST}:${ADMIN_BACKEND_PORT} ===${NC}"
if nc -z -w 3 "${BACKEND_HOST}" "${ADMIN_BACKEND_PORT}" 2>/dev/null; then
    echo "  Admin port reachable - OK"
else
    echo -e "${RED}ERROR: Cannot reach ${BACKEND_HOST}:${ADMIN_BACKEND_PORT}${NC}"
    echo ""
    echo "  Possible causes:"
    echo "    - Your laptop public IP is not in admin_cidr."
    echo "      Update: pulumi config set relay-xdp-infra:admin_cidr \"\$(curl -4 -s ifconfig.me)/32\" --stack ${STACK:-staging}"
    echo "      Then:   pulumi up --yes --stack ${STACK:-staging} --cwd infra"
    echo "    - The backend EC2 instance is not yet running."
    echo "    - Wrong BACKEND_HOST (${BACKEND_HOST})."
    exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# Wait for backend readiness (polls /health on public port, max 90s)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}=== Waiting for backend readiness ===${NC}"
MAX_WAIT=90
WAITED=0
while [ "${WAITED}" -lt "${MAX_WAIT}" ]; do
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${BACKEND_URL}/health" 2>/dev/null) || STATUS="000"
    if [ "${STATUS}" = "200" ]; then
        echo "  Backend /health returned 200 after ${WAITED}s"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    if [ $((WAITED % 15)) -eq 0 ]; then
        echo "  Waiting... (${WAITED}s, last status: ${STATUS})"
    fi
done

if [ "${WAITED}" -ge "${MAX_WAIT}" ]; then
    echo -e "${RED}ERROR: Backend did not respond within ${MAX_WAIT}s - giving up.${NC}"
    echo "  Check: ssh ubuntu@${BACKEND_HOST} 'journalctl -u relay-backend --since \"5 min ago\" | tail -50'"
    exit 1
fi

# ---------------------------------------------------------------------------
# Wait for relay update cycles (1 Hz loop, relays register after ~3-5 cycles)
# ---------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}=== Waiting 15s for relay update cycles ===${NC}"
sleep 15
echo "  Done"
echo ""

# ---------------------------------------------------------------------------
# Assertion helpers (identical contract to compose-test.sh)
# ---------------------------------------------------------------------------
assert_http_ok() {
    local desc="$1"
    local url="$2"
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null) || status="000"
    if [ "${status}" = "200" ]; then
        echo -e "  ${GREEN}PASS${NC} [${status}] ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} [${status}] ${desc} (expected 200)"
        FAILED=$((FAILED + 1))
    fi
}

assert_http_status() {
    local desc="$1"
    local url="$2"
    local expected="$3"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null) || status="000"
    if [ "${status}" = "${expected}" ]; then
        echo -e "  ${GREEN}PASS${NC} [${status}] ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} [${status}] ${desc} (expected ${expected})"
        FAILED=$((FAILED + 1))
    fi
}

assert_body_contains() {
    local desc="$1"
    local url="$2"
    local expected="$3"
    local body
    body=$(curl -sf "${url}" 2>/dev/null) || body=""
    if echo "${body}" | grep -q "${expected}"; then
        echo -e "  ${GREEN}PASS${NC} ${desc} (contains '${expected}')"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} ${desc} (expected body to contain '${expected}')"
        echo "  Body (first 500 chars): ${body:0:500}"
        FAILED=$((FAILED + 1))
    fi
}

assert_body_nonempty() {
    local desc="$1"
    local url="$2"
    local body
    body=$(curl -sf "${url}" 2>/dev/null) || body=""
    if [ -n "${body}" ]; then
        local len=${#body}
        echo -e "  ${GREEN}PASS${NC} ${desc} (${len} bytes)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} ${desc} (expected non-empty body)"
        FAILED=$((FAILED + 1))
    fi
}

assert_body_line_count_gte() {
    local desc="$1"
    local url="$2"
    local pattern="$3"
    local min_count="$4"
    local body count
    body=$(curl -sf "${url}" 2>/dev/null) || body=""
    count=$(echo "${body}" | grep -c "${pattern}" 2>/dev/null) || count=0
    if [ "${count}" -ge "${min_count}" ]; then
        echo -e "  ${GREEN}PASS${NC} ${desc} (${count} >= ${min_count} matches)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} ${desc} (expected >= ${min_count} lines matching '${pattern}', got ${count})"
        echo "  Body (first 500 chars): ${body:0:500}"
        FAILED=$((FAILED + 1))
    fi
}

# ---------------------------------------------------------------------------
# Assert phase
# ---------------------------------------------------------------------------
echo -e "${YELLOW}=== Running assertions (backend: ${BACKEND_HOST}, ${RELAY_COUNT} relays) ===${NC}"
echo ""

# 1. GET /health - public port (Backend alive)
assert_http_ok \
    "1. GET /health returns 200" \
    "${BACKEND_URL}/health"

# 2. GET /ready - public port (Leader election + startup delay complete)
assert_http_ok \
    "2. GET /ready returns 200" \
    "${BACKEND_URL}/ready"

# 3. GET /active_relays - each relay id must appear in body (admin port)
#    Loops over RELAY_IDS derived from Pulumi output so naming is always in
#    sync with the deployed stack (no hardcoded relay-a/b/c).
for relay_id in ${RELAY_IDS:-}; do
    assert_body_contains \
        "3. GET /active_relays contains ${relay_id}" \
        "${ADMIN_BACKEND_URL}/active_relays" \
        "${relay_id}"
done

# 4. GET /relays - at least RELAY_COUNT "online" rows in CSV (admin port)
assert_body_line_count_gte \
    "4. GET /relays has ${RELAY_COUNT} online entries" \
    "${ADMIN_BACKEND_URL}/relays" \
    "online" \
    "${RELAY_COUNT}"

# 5. GET /cost_matrix - non-empty (admin port)
assert_body_nonempty \
    "5. GET /cost_matrix is non-empty" \
    "${ADMIN_BACKEND_URL}/cost_matrix"

# 6. GET /costs - non-empty (admin port)
#    On real hardware ping-pong is reflected by XDP, so real RTT values appear.
#    (Unlike compose where RELAY_NO_BPF=1 may show 255.)
assert_body_nonempty \
    "6. GET /costs returns data" \
    "${ADMIN_BACKEND_URL}/costs"

# 7. GET /route_matrix - non-empty (admin port)
assert_body_nonempty \
    "7. GET /route_matrix is non-empty" \
    "${ADMIN_BACKEND_URL}/route_matrix"

# 8. GET /metrics - contains Prometheus metric names (admin port)
assert_body_contains \
    "8. GET /metrics contains backend metrics" \
    "${ADMIN_BACKEND_URL}/metrics" \
    "relay_backend_"

# 9. GET /relay_counters/<id> - HTTP 200 per relay (admin port)
#    Loops over every relay in the stack so a missing relay fails loudly.
for relay_id in ${RELAY_IDS:-}; do
    assert_http_ok \
        "9. GET /relay_counters/${relay_id} returns 200" \
        "${ADMIN_BACKEND_URL}/relay_counters/${relay_id}"
done

# 10a-c. Port-separation: admin paths must NOT leak to public port (8090),
#        public paths must NOT leak to admin port (8091).
echo ""
echo "  -- Port separation checks --"
assert_http_status \
    "10a. /metrics on public port (${BACKEND_PORT}) returns 404" \
    "${BACKEND_URL}/metrics" \
    "404"
assert_http_status \
    "10b. /cost_matrix on public port (${BACKEND_PORT}) returns 404" \
    "${BACKEND_URL}/cost_matrix" \
    "404"
assert_http_status \
    "10c. /relay_update on admin port (${ADMIN_BACKEND_PORT}) returns 404" \
    "${ADMIN_BACKEND_URL}/relay_update" \
    "404"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
TOTAL=$((PASSED + FAILED))
echo -e "${YELLOW}=== Results: ${PASSED}/${TOTAL} passed ===${NC}"

if [ "${FAILED}" -gt 0 ]; then
    echo -e "${RED}${FAILED} assertion(s) failed!${NC}"
    echo ""
    echo "  Stack is intentionally left alive for inspection."
    echo "  When done: make e2e-teardown STACK=${STACK:-staging}"
    exit 1
else
    echo -e "${GREEN}All assertions passed!${NC}"
    exit 0
fi

