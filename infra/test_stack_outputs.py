#!/usr/bin/env python3
"""
test_stack_outputs.py - Unit tests for infra/stack_outputs.py.

Tests parse_e2e_env() against mock Pulumi outputs (no real AWS or pulumi CLI
needed). Mirrors the style of test_inventory_gen.py.

Usage:
  python infra/test_stack_outputs.py

Exit code 0 = all checks pass.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stack_outputs import (  # noqa: E402
    BACKEND_ADMIN_PORT,
    BACKEND_PUBLIC_PORT,
    StackEnv,
    format_env,
    format_json,
    parse_e2e_env,
)

# ---------------------------------------------------------------------------
# Mock outputs - same shape as __main__.py exports
# ---------------------------------------------------------------------------

MOCK_3_RELAY = {
    "relay_nodes": {
        "relay-staging-3": {
            "public_ip": "203.0.113.13",
            "private_ip": "10.3.0.11",
            "instance_id": "i-0000000000000013",
            "region": "ap-southeast-1",
            "name": "relay-staging-3",
        },
        "relay-staging-1": {
            "public_ip": "203.0.113.11",
            "private_ip": "10.1.0.11",
            "instance_id": "i-0000000000000011",
            "region": "us-east-1",
            "name": "relay-staging-1",
        },
        "relay-staging-2": {
            "public_ip": "203.0.113.12",
            "private_ip": "10.2.0.11",
            "instance_id": "i-0000000000000012",
            "region": "eu-west-1",
            "name": "relay-staging-2",
        },
    },
    "backend": {
        "public_ip": "203.0.113.20",
        "private_ip": "10.1.0.20",
        "instance_id": "i-0000000000000020",
        "region": "us-east-1",
        "name": "backend-staging-1",
    },
    "stack": "staging",
}

MOCK_1_RELAY = {
    "relay_nodes": {
        "relay-staging-1": {
            "public_ip": "10.0.0.1",
            "private_ip": "10.0.0.1",
            "instance_id": "i-0001",
            "region": "us-east-1",
            "name": "relay-staging-1",
        },
    },
    "backend": {
        "public_ip": "10.0.0.2",
        "private_ip": "10.0.0.2",
        "instance_id": "i-0002",
        "region": "us-east-1",
        "name": "backend-staging-1",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0


def ok(msg: str) -> None:
    global PASS
    PASS += 1
    print(f"  OK  {msg}")


def fail(msg: str) -> None:
    global FAIL
    FAIL += 1
    print(f"  FAIL {msg}", file=sys.stderr)


def assert_eq(label: str, got, expected) -> None:
    if got == expected:
        ok(label)
    else:
        fail(f"{label}: got {got!r}, expected {expected!r}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_parse_3_relays() -> None:
    print("\n=== test_parse_3_relays ===")
    env = parse_e2e_env(MOCK_3_RELAY)

    assert_eq("backend_host", env.backend_host, "203.0.113.20")
    assert_eq("backend_port", env.backend_port, BACKEND_PUBLIC_PORT)
    assert_eq("admin_backend_port", env.admin_backend_port, BACKEND_ADMIN_PORT)

    # relay_ids must be sorted lexicographically
    assert_eq(
        "relay_ids sorted",
        env.relay_ids,
        ["relay-staging-1", "relay-staging-2", "relay-staging-3"],
    )
    assert_eq(
        "relay_public_ips in id order",
        env.relay_public_ips,
        ["203.0.113.11", "203.0.113.12", "203.0.113.13"],
    )


def test_parse_1_relay() -> None:
    print("\n=== test_parse_1_relay ===")
    env = parse_e2e_env(MOCK_1_RELAY)

    assert_eq("backend_host", env.backend_host, "10.0.0.2")
    assert_eq("relay_ids length", len(env.relay_ids), 1)
    assert_eq("relay_ids[0]", env.relay_ids[0], "relay-staging-1")
    assert_eq("relay_public_ips[0]", env.relay_public_ips[0], "10.0.0.1")


def test_port_constants() -> None:
    print("\n=== test_port_constants ===")
    assert_eq("BACKEND_PUBLIC_PORT", BACKEND_PUBLIC_PORT, 8090)
    assert_eq("BACKEND_ADMIN_PORT", BACKEND_ADMIN_PORT, 8091)


def test_format_env() -> None:
    print("\n=== test_format_env ===")
    env = StackEnv(
        backend_host="1.2.3.4",
        backend_port=8090,
        admin_backend_port=8091,
        relay_public_ips=["10.0.0.1", "10.0.0.2"],
        relay_ids=["relay-staging-1", "relay-staging-2"],
    )
    output = format_env(env)

    assert_eq(
        "contains BACKEND_HOST",
        "export BACKEND_HOST=1.2.3.4" in output,
        True,
    )
    assert_eq(
        "contains BACKEND_PORT",
        "export BACKEND_PORT=8090" in output,
        True,
    )
    assert_eq(
        "contains ADMIN_BACKEND_PORT",
        "export ADMIN_BACKEND_PORT=8091" in output,
        True,
    )
    assert_eq(
        "contains RELAY_PUBLIC_IPS with both IPs",
        "10.0.0.1 10.0.0.2" in output,
        True,
    )
    assert_eq(
        "contains RELAY_IDS with both ids",
        "relay-staging-1 relay-staging-2" in output,
        True,
    )


def test_format_json() -> None:
    print("\n=== test_format_json ===")
    import json as _json

    env = StackEnv(
        backend_host="1.2.3.4",
        backend_port=8090,
        admin_backend_port=8091,
        relay_public_ips=["10.0.0.1"],
        relay_ids=["relay-staging-1"],
    )
    parsed = _json.loads(format_json(env))

    assert_eq("json.backend_host", parsed["backend_host"], "1.2.3.4")
    assert_eq("json.backend_port", parsed["backend_port"], 8090)
    assert_eq("json.admin_backend_port", parsed["admin_backend_port"], 8091)
    assert_eq("json.relay_public_ips", parsed["relay_public_ips"], ["10.0.0.1"])
    assert_eq("json.relay_ids", parsed["relay_ids"], ["relay-staging-1"])


def test_missing_backend_exits() -> None:
    """parse_e2e_env must exit(1) when backend is absent."""
    print("\n=== test_missing_backend_exits ===")
    import os
    import subprocess

    code = (
        "import sys; sys.path.insert(0,'infra'); "
        "from stack_outputs import parse_e2e_env; "
        "parse_e2e_env({'relay_nodes': {'r': {'public_ip': '1.2.3.4'}}})"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert_eq("exits non-zero on missing backend", result.returncode, 1)


def test_missing_relay_nodes_exits() -> None:
    """parse_e2e_env must exit(1) when relay_nodes is absent."""
    print("\n=== test_missing_relay_nodes_exits ===")
    import subprocess

    code = (
        "import sys; sys.path.insert(0,'infra'); "
        "from stack_outputs import parse_e2e_env; "
        "parse_e2e_env({'backend': {'public_ip': '1.2.3.4'}})"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert_eq("exits non-zero on missing relay_nodes", result.returncode, 1)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    test_port_constants()
    test_parse_3_relays()
    test_parse_1_relay()
    test_format_env()
    test_format_json()
    test_missing_backend_exits()
    test_missing_relay_nodes_exits()

    print(f"\nResults: {PASS} passed, {FAIL} failed")
    if FAIL:
        print(f"FAILED - {FAIL} error(s)")
        return 1
    print("PASSED - all stack_outputs checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

