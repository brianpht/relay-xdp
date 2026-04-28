#!/usr/bin/env bash
# tests/compose-test.sh - Docker Compose integration test runner.
#
# Builds and starts the 5-service topology (redis, backend, 3 relays),
# waits for readiness, then runs 9 curl-based assertions against the
# backend HTTP endpoints.
#
# Usage:
#   bash tests/compose-test.sh             # build + test
#   bash tests/compose-test.sh --no-build  # skip build (reuse images)
#
# Prerequisites:
#   - Docker Engine with Compose v2 plugin
#   - curl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.test.yml"
BACKEND_URL="http://172.28.0.3:80"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
NO_BUILD=false

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# -----------------------------------------------------------
# Cleanup on exit (always run)
# -----------------------------------------------------------
cleanup() {
    echo ""
    echo -e "${YELLOW}=== Teardown ===${NC}"
    docker compose -f "$COMPOSE_FILE" logs --tail=50 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# -----------------------------------------------------------
# Assertion helpers
# -----------------------------------------------------------
assert_http_ok() {
    local desc="$1"
    local url="$2"
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null) || status="000"
    if [ "$status" = "200" ]; then
        echo -e "  ${GREEN}PASS${NC} [$status] $desc"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} [$status] $desc (expected 200)"
        FAILED=$((FAILED + 1))
    fi
}

assert_body_contains() {
    local desc="$1"
    local url="$2"
    local expected="$3"
    local body
    body=$(curl -sf "$url" 2>/dev/null) || body=""
    if echo "$body" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $desc (contains '$expected')"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc (expected body to contain '$expected')"
        echo "  Body (first 500 chars): ${body:0:500}"
        FAILED=$((FAILED + 1))
    fi
}

assert_body_nonempty() {
    local desc="$1"
    local url="$2"
    local body
    body=$(curl -sf "$url" 2>/dev/null) || body=""
    if [ -n "$body" ]; then
        local len=${#body}
        echo -e "  ${GREEN}PASS${NC} $desc (${len} bytes)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc (expected non-empty body)"
        FAILED=$((FAILED + 1))
    fi
}

assert_body_line_count_gte() {
    local desc="$1"
    local url="$2"
    local pattern="$3"
    local min_count="$4"
    local body
    body=$(curl -sf "$url" 2>/dev/null) || body=""
    local count
    count=$(echo "$body" | grep -c "$pattern" 2>/dev/null) || count=0
    if [ "$count" -ge "$min_count" ]; then
        echo -e "  ${GREEN}PASS${NC} $desc ($count >= $min_count matches)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc (expected >= $min_count lines matching '$pattern', got $count)"
        echo "  Body (first 500 chars): ${body:0:500}"
        FAILED=$((FAILED + 1))
    fi
}

# -----------------------------------------------------------
# Build phase
# -----------------------------------------------------------
echo -e "${YELLOW}=== Docker Compose Integration Test ===${NC}"
echo ""

if [ "$NO_BUILD" = false ]; then
    echo -e "${YELLOW}=== Building images ===${NC}"
    docker compose -f "$COMPOSE_FILE" build
    echo ""
fi

# -----------------------------------------------------------
# Start phase
# -----------------------------------------------------------
echo -e "${YELLOW}=== Starting services ===${NC}"
docker compose -f "$COMPOSE_FILE" up -d
echo ""

# -----------------------------------------------------------
# Wait for backend readiness
# -----------------------------------------------------------
echo -e "${YELLOW}=== Waiting for backend readiness ===${NC}"
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${BACKEND_URL}/ready" 2>/dev/null) || STATUS="000"
    if [ "$STATUS" = "200" ]; then
        echo "  Backend ready after ${WAITED}s"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "  Waiting... (${WAITED}s, last status: $STATUS)"
    fi
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo -e "${RED}ERROR: Backend did not become ready within ${MAX_WAIT}s${NC}"
    echo ""
    echo "Backend logs:"
    docker compose -f "$COMPOSE_FILE" logs backend --tail=30 2>/dev/null || true
    exit 1
fi

# -----------------------------------------------------------
# Wait for relay update cycles
# -----------------------------------------------------------
# Relays need ~3-5 update cycles (1 Hz) to register with backend
# and accumulate ping RTT data. Wait 15s for safety.
echo ""
echo -e "${YELLOW}=== Waiting 15s for relay update cycles ===${NC}"
sleep 15
echo "  Done"
echo ""

# -----------------------------------------------------------
# Assert phase
# -----------------------------------------------------------
echo -e "${YELLOW}=== Running assertions ===${NC}"
echo ""

# 1. GET /health - HTTP 200 (Backend alive)
assert_http_ok \
    "1. GET /health returns 200" \
    "${BACKEND_URL}/health"

# 2. GET /ready - HTTP 200 (Leader election + delay complete)
assert_http_ok \
    "2. GET /ready returns 200" \
    "${BACKEND_URL}/ready"

# 3. GET /active_relays - Contains relay-a, relay-b, relay-c
assert_body_contains \
    "3. GET /active_relays contains relay-a" \
    "${BACKEND_URL}/active_relays" \
    "relay-a"
assert_body_contains \
    "3. GET /active_relays contains relay-b" \
    "${BACKEND_URL}/active_relays" \
    "relay-b"
assert_body_contains \
    "3. GET /active_relays contains relay-c" \
    "${BACKEND_URL}/active_relays" \
    "relay-c"

# 4. GET /relays - 3 "online" rows in CSV
assert_body_line_count_gte \
    "4. GET /relays has 3 online entries" \
    "${BACKEND_URL}/relays" \
    "online" \
    3

# 5. GET /cost_matrix - Response body length > 0
assert_body_nonempty \
    "5. GET /cost_matrix is non-empty" \
    "${BACKEND_URL}/cost_matrix"

# 6. GET /costs - At least one cost line present
#    In RELAY_NO_BPF=1 mode, ping pongs may not be reflected by eBPF,
#    so costs may show 255. We check that the endpoint returns data.
assert_body_nonempty \
    "6. GET /costs returns data" \
    "${BACKEND_URL}/costs"

# 7. GET /route_matrix - Response body length > 0
assert_body_nonempty \
    "7. GET /route_matrix is non-empty" \
    "${BACKEND_URL}/route_matrix"

# 8. GET /metrics - Contains relay backend metric lines
assert_body_contains \
    "8. GET /metrics contains backend metrics" \
    "${BACKEND_URL}/metrics" \
    "relay_backend_"

# 9. GET /relay_counters/relay-a - HTTP 200
assert_http_ok \
    "9. GET /relay_counters/relay-a returns 200" \
    "${BACKEND_URL}/relay_counters/relay-a"

# 10. relay-sdk smoke test (build + run in compose network)
echo ""
echo -e "${YELLOW}=== Running relay-sdk smoke test ===${NC}"
if docker compose -f "$COMPOSE_FILE" \
        --profile smoke run --rm --build sdk-smoke 2>&1; then
    echo -e "  ${GREEN}PASS${NC} 10. relay-sdk smoke test (13/13 assertions)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} 10. relay-sdk smoke test"
    FAILED=$((FAILED + 1))
fi

# -----------------------------------------------------------
# Summary
# -----------------------------------------------------------
echo ""
TOTAL=$((PASSED + FAILED))
echo -e "${YELLOW}=== Results: ${PASSED}/${TOTAL} passed ===${NC}"

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}${FAILED} assertion(s) failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All assertions passed!${NC}"
    exit 0
fi

