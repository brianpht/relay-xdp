#!/usr/bin/env python3
"""
test_admin_cidr_validation.py - Unit tests for `_validate_admin_cidr` (P1-04).

The validation has three failure modes the audit cares about:
  1. Placeholder REQUIRED_OVERRIDE rejected on every stack.
  2. 0.0.0.0/0 rejected on production.
  3. Narrow CIDR (e.g. /32) accepted on every stack.

Production refusal of `::/0` is also tested for IPv6 wide-open.

Usage:
  python infra/test_admin_cidr_validation.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pulumi  # noqa: E402

from config import _validate_admin_cidr  # noqa: E402


def assert_raises(fn, label: str) -> None:
    try:
        fn()
    except pulumi.RunError as e:
        print(f"  PASS: {label} -> {e}")
        return
    print(f"  FAIL: {label} did not raise")
    sys.exit(1)


def assert_ok(fn, label: str) -> None:
    try:
        fn()
    except pulumi.RunError as e:
        print(f"  FAIL: {label} unexpectedly raised: {e}")
        sys.exit(1)
    print(f"  PASS: {label}")


def main() -> int:
    print("test_admin_cidr_validation (P1-04)")

    # 1. REQUIRED_OVERRIDE rejected on every stack.
    assert_raises(
        lambda: _validate_admin_cidr("REQUIRED_OVERRIDE", "production"),
        "REQUIRED_OVERRIDE rejected on production",
    )
    assert_raises(
        lambda: _validate_admin_cidr("REQUIRED_OVERRIDE", "staging"),
        "REQUIRED_OVERRIDE rejected on staging",
    )

    # 2. Wide-open rejected on production.
    assert_raises(
        lambda: _validate_admin_cidr("0.0.0.0/0", "production"),
        "0.0.0.0/0 rejected on production",
    )
    assert_raises(
        lambda: _validate_admin_cidr("::/0", "production"),
        "::/0 rejected on production",
    )

    # 3. Wide-open is a warning-not-error on staging today (operator
    #    convenience; the placeholder still forced an explicit choice).
    assert_ok(
        lambda: _validate_admin_cidr("0.0.0.0/0", "staging"),
        "0.0.0.0/0 accepted on staging (explicit operator choice)",
    )

    # 4. Narrow CIDR accepted on every stack.
    assert_ok(
        lambda: _validate_admin_cidr("203.0.113.5/32", "production"),
        "203.0.113.5/32 accepted on production",
    )
    assert_ok(
        lambda: _validate_admin_cidr("10.0.0.0/8", "staging"),
        "10.0.0.0/8 accepted on staging",
    )

    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())