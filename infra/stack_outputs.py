#!/usr/bin/env python3
"""
stack_outputs.py - Shared Pulumi stack output parser for relay-xdp tooling.

Provides get_stack_outputs() (imported by inventory_gen.py and tests/e2e-deployed.sh)
and a CLI that emits shell-eval-able env vars for the E2E test harness.

Usage:
  python infra/stack_outputs.py --stack staging --format env
  python infra/stack_outputs.py --stack production --format json

Output (--format env):
  export BACKEND_HOST=1.2.3.4
  export BACKEND_PORT=8090
  export ADMIN_BACKEND_PORT=8091
  export RELAY_PUBLIC_IPS="10.x.x.x 10.y.y.y 10.z.z.z"
  export RELAY_IDS="relay-staging-1 relay-staging-2 relay-staging-3"
  export BENCH_HOST=1.2.3.5          (only when bench node is provisioned)
  export SERVER_BACKEND_URL=http://1.2.3.4:8180  (only when exported by stack)

Output (--format json):
  {
    "backend_host": "1.2.3.4",
    "backend_port": 8090,
    "admin_backend_port": 8091,
    "relay_public_ips": ["10.x.x.x", ...],
    "relay_ids": ["relay-staging-1", ...],
    "bench_host": "1.2.3.5",
    "server_backend_url": "http://1.2.3.4:8180"
  }

Requirements:
  - pulumi CLI installed and authenticated (pulumi login ...)
  - Target stack deployed (pulumi up --stack <stack>)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

# Repo root relative to this file (infra/ -> ../)
REPO_ROOT = Path(__file__).resolve().parent.parent
INFRA_DIR = REPO_ROOT / "infra"

# Production port constants - must match infra/network.py SG definitions.
BACKEND_PUBLIC_PORT = 8090   # TCP: relay_update POST + health (open to 0.0.0.0/0)
BACKEND_ADMIN_PORT  = 8091   # TCP: topology, metrics, cost_matrix (admin_cidr only)


@dataclass
class StackEnv:
    """Parsed E2E-relevant values from a Pulumi stack output."""
    backend_host: str
    backend_port: int
    admin_backend_port: int
    relay_public_ips: List[str]
    relay_ids: List[str]
    # Empty string when bench node is not provisioned (bench_enabled: false).
    bench_host: str = ""
    # server-backend public URL (http://IP:8180). Empty string when not exported.
    server_backend_url: str = ""


def get_stack_outputs(stack: str) -> dict:
    """
    Run `pulumi stack output --json --stack <stack>` and return the parsed dict.

    Exits with a clear error message if the pulumi CLI fails or output is not
    valid JSON. This function is imported directly by inventory_gen.py so both
    tools stay in sync with the Pulumi output shape.
    """
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--stack", stack],
        cwd=str(INFRA_DIR),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"ERROR: pulumi stack output failed:\n{result.stderr}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(
            f"ERROR: failed to parse pulumi output as JSON: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def parse_e2e_env(outputs: dict) -> StackEnv:
    """
    Extract E2E-relevant fields from raw Pulumi stack outputs.

    Expected output shape (from infra/__main__.py exports):
      {
        "backend": {
          "public_ip": "1.2.3.4",
          "private_ip": "...",
          "instance_id": "...",
          "region": "...",
          "name": "backend-staging-1"
        },
        "relay_nodes": {
          "relay-staging-1": { "public_ip": "...", ... },
          "relay-staging-2": { "public_ip": "...", ... },
          "relay-staging-3": { "public_ip": "...", ... }
        }
      }

    Exits if required fields are missing (stack not deployed).
    """
    backend: dict = outputs.get("backend", {})
    relay_nodes: dict = outputs.get("relay_nodes", {})

    if not backend or not backend.get("public_ip"):
        print(
            "ERROR: 'backend.public_ip' missing from stack outputs.\n"
            "       Has `pulumi up` been run for this stack?",
            file=sys.stderr,
        )
        sys.exit(1)

    if not relay_nodes:
        print(
            "ERROR: 'relay_nodes' missing from stack outputs.\n"
            "       Has `pulumi up` been run for this stack?",
            file=sys.stderr,
        )
        sys.exit(1)

    # Sort relay ids for deterministic ordering across runs.
    sorted_ids = sorted(relay_nodes.keys())
    missing_ips = [r for r in sorted_ids if not relay_nodes[r].get("public_ip")]
    if missing_ips:
        print(
            f"ERROR: relay nodes missing public_ip: {missing_ips}",
            file=sys.stderr,
        )
        sys.exit(1)

    # bench host - optional; empty string when bench_enabled is false.
    bench: dict = outputs.get("bench") or {}
    bench_host: str = bench.get("public_ip", "") if bench else ""

    # server_backend_url - exported by infra/__main__.py as a top-level string.
    server_backend_url: str = outputs.get("server_backend_url", "")

    return StackEnv(
        backend_host=backend["public_ip"],
        backend_port=BACKEND_PUBLIC_PORT,
        admin_backend_port=BACKEND_ADMIN_PORT,
        relay_public_ips=[relay_nodes[r]["public_ip"] for r in sorted_ids],
        relay_ids=sorted_ids,
        bench_host=bench_host,
        server_backend_url=server_backend_url,
    )


def format_env(env: StackEnv) -> str:
    """
    Render StackEnv as shell export statements for `eval`.

    Usage in shell:
      eval $(python infra/stack_outputs.py --stack staging --format env)
    """
    lines = [
        f'export BACKEND_HOST={env.backend_host}',
        f'export BACKEND_PORT={env.backend_port}',
        f'export ADMIN_BACKEND_PORT={env.admin_backend_port}',
        f'export RELAY_PUBLIC_IPS="{" ".join(env.relay_public_ips)}"',
        f'export RELAY_IDS="{" ".join(env.relay_ids)}"',
    ]
    if env.bench_host:
        lines.append(f'export BENCH_HOST={env.bench_host}')
    if env.server_backend_url:
        lines.append(f'export SERVER_BACKEND_URL={env.server_backend_url}')
    return "\n".join(lines)


def format_json(env: StackEnv) -> str:
    """Render StackEnv as pretty-printed JSON."""
    return json.dumps(
        {
            "backend_host": env.backend_host,
            "backend_port": env.backend_port,
            "admin_backend_port": env.admin_backend_port,
            "relay_public_ips": env.relay_public_ips,
            "relay_ids": env.relay_ids,
            "bench_host": env.bench_host,
            "server_backend_url": env.server_backend_url,
        },
        indent=2,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Emit E2E-relevant values from a Pulumi stack as env exports or JSON.\n"
            "Imported by inventory_gen.py; also callable directly from shell scripts."
        )
    )
    parser.add_argument(
        "--stack",
        required=True,
        choices=["production", "staging"],
        help="Pulumi stack name.",
    )
    parser.add_argument(
        "--format",
        choices=["env", "json"],
        default="env",
        help="Output format: 'env' for shell eval, 'json' for machine parsing (default: env).",
    )
    args = parser.parse_args()

    outputs = get_stack_outputs(args.stack)
    env = parse_e2e_env(outputs)

    if args.format == "env":
        print(format_env(env))
    else:
        print(format_json(env))


if __name__ == "__main__":
    main()

