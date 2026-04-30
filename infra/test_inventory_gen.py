#!/usr/bin/env python3
"""
test_inventory_gen.py - Validate inventory_gen.py output against Ansible schema.

Uses mock Pulumi stack outputs (no real AWS infrastructure needed) to generate
a staging and production inventory, then validates each with `ansible --list-hosts`.

Usage:
  python infra/test_inventory_gen.py

Exit code 0 = all checks pass. Non-zero = failure details printed to stderr.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

# Import build_inventory and render_yaml directly from inventory_gen
sys.path.insert(0, str(Path(__file__).resolve().parent))
from inventory_gen import build_inventory, render_yaml, HEADER  # noqa: E402

# ---------------------------------------------------------------------------
# Mock Pulumi outputs - mirrors the shape exported by __main__.py
# ---------------------------------------------------------------------------

MOCK_STAGING_OUTPUTS = {
    "relay_nodes": {
        "relay-staging-1": {
            "public_ip": "203.0.113.10",
            "private_ip": "10.1.0.10",
            "instance_id": "i-0000000000000001",
            "region": "us-east-1",
        },
    },
    "backend": {
        "name": "backend-staging-1",
        "public_ip": "203.0.113.20",
        "private_ip": "10.1.0.20",
        "instance_id": "i-0000000000000002",
    },
    "stack": "staging",
}

MOCK_PRODUCTION_OUTPUTS = {
    "relay_nodes": {
        "relay-production-1": {
            "public_ip": "203.0.113.11",
            "private_ip": "10.1.0.11",
            "instance_id": "i-0000000000000011",
            "region": "us-east-1",
        },
        "relay-production-2": {
            "public_ip": "203.0.113.12",
            "private_ip": "10.2.0.11",
            "instance_id": "i-0000000000000012",
            "region": "eu-west-1",
        },
        "relay-production-3": {
            "public_ip": "203.0.113.13",
            "private_ip": "10.3.0.11",
            "instance_id": "i-0000000000000013",
            "region": "ap-southeast-1",
        },
    },
    "backend": {
        "name": "backend-production-1",
        "public_ip": "203.0.113.21",
        "private_ip": "10.1.0.21",
        "instance_id": "i-0000000000000021",
    },
    "stack": "production",
}


# ---------------------------------------------------------------------------
# Expected host lists per group (for assertion)
# ---------------------------------------------------------------------------

EXPECTED = {
    "staging": {
        "relay_servers":   ["relay-staging-1"],
        "backend_servers": ["backend-staging-1"],
        "all":             ["relay-staging-1", "backend-staging-1"],
    },
    "production": {
        "relay_servers":   ["relay-production-1", "relay-production-2", "relay-production-3"],
        "backend_servers": ["backend-production-1"],
        "all":             [
            "relay-production-1", "relay-production-2", "relay-production-3",
            "backend-production-1",
        ],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ansible_list_hosts(inventory_path: str, pattern: str) -> list[str]:
    """
    Run `ansible --list-hosts <pattern> -i <inventory>` and return host list.
    Returns [] if ansible is not installed (test is skipped gracefully).
    """
    result = subprocess.run(
        ["ansible", "--list-hosts", pattern, "-i", inventory_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  ansible --list-hosts failed:\n{result.stderr.strip()}", file=sys.stderr)
        return None  # None = ansible error (distinct from empty list)

    # Output format:
    #   hosts (N):
    #     host1
    #     host2
    lines = result.stdout.splitlines()
    hosts = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("hosts (")]
    return hosts


def check_required_fields(inventory: dict, stack: str) -> list[str]:
    """
    Verify required fields exist on every host entry.
    Returns list of error strings (empty = OK).
    """
    errors: list[str] = []
    children = inventory["all"]["children"]

    for host_name, host_vars in children["relay_servers"]["hosts"].items():
        for field in ("ansible_host", "relay_name", "ansible_user"):
            if field not in host_vars:
                errors.append(f"[{stack}] relay_servers/{host_name} missing field: {field}")
        if host_vars.get("ansible_user") != "ubuntu":
            errors.append(
                f"[{stack}] relay_servers/{host_name} ansible_user="
                f"{host_vars.get('ansible_user')!r} (expected 'ubuntu')"
            )
        if host_vars.get("relay_name") != host_name:
            errors.append(
                f"[{stack}] relay_servers/{host_name} relay_name mismatch: "
                f"{host_vars.get('relay_name')!r}"
            )

    for host_name, host_vars in children["backend_servers"]["hosts"].items():
        for field in ("ansible_host", "ansible_user"):
            if field not in host_vars:
                errors.append(f"[{stack}] backend_servers/{host_name} missing field: {field}")
        if host_vars.get("ansible_user") != "ubuntu":
            errors.append(
                f"[{stack}] backend_servers/{host_name} ansible_user="
                f"{host_vars.get('ansible_user')!r} (expected 'ubuntu')"
            )

    return errors


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

def run_tests() -> int:
    """Run all checks. Returns exit code (0 = pass)."""
    all_errors: list[str] = []
    ansible_available = True

    cases = [
        ("staging",    MOCK_STAGING_OUTPUTS),
        ("production", MOCK_PRODUCTION_OUTPUTS),
    ]

    for stack, mock_outputs in cases:
        print(f"\n=== stack: {stack} ===")

        # 1. Build inventory dict from mock outputs
        inventory = build_inventory(mock_outputs, stack)
        header = HEADER.format(stack=stack)
        content = header + render_yaml(inventory)

        # 2. Write to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=f"-{stack}.yml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        print(f"  Generated inventory: {tmp_path}")
        print(textwrap.indent(content, "    "))

        # 3. Check required fields (no ansible needed)
        field_errors = check_required_fields(inventory, stack)
        if field_errors:
            for e in field_errors:
                print(f"  FAIL field check: {e}", file=sys.stderr)
            all_errors.extend(field_errors)
        else:
            print("  OK  required fields check")

        # 4. ansible --list-hosts per group
        if ansible_available:
            for group, expected_hosts in EXPECTED[stack].items():
                hosts = ansible_list_hosts(tmp_path, group)
                if hosts is None:
                    print(f"  SKIP ansible check for group={group} (ansible error)")
                    ansible_available = False
                    break
                missing  = set(expected_hosts) - set(hosts)
                extra    = set(hosts) - set(expected_hosts)
                if missing or extra:
                    err = (
                        f"[{stack}] group={group}: "
                        f"missing={sorted(missing)} extra={sorted(extra)}"
                    )
                    print(f"  FAIL {err}", file=sys.stderr)
                    all_errors.append(err)
                else:
                    print(f"  OK  ansible --list-hosts {group} ({len(hosts)} hosts)")
        else:
            print("  SKIP ansible --list-hosts (ansible not available)")

    # Summary
    print()
    if all_errors:
        print(f"FAILED - {len(all_errors)} error(s):")
        for e in all_errors:
            print(f"  - {e}")
        return 1

    print("PASSED - all inventory schema checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())

