"""
config.py - Stack config reader and shared constants for relay-xdp-infra.

All Pulumi stack config is read once here. Every other module imports from
this module - no direct pulumi.Config calls outside this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import pulumi

# ---------------------------------------------------------------------------
# AMI constants
# ---------------------------------------------------------------------------

# Canonical (Ubuntu) AWS owner ID - stable, does not change.
CANONICAL_OWNER_ID = "099720109477"

# Ubuntu 22.04 LTS (Jammy) x86_64 HWE kernel on EBS SSD.
#
# Ubuntu 22.04 LTS support: Until April 2032 (5-year baseline + 5-year extended).
# HWE (Hardware Enablement) kernel: auto-updates to latest stable (currently 6.17.0-*).
# Kernel requirement: >=6.5 for BTF and kfunc support (XDP kernel module).
#
# Key guarantee: Every new AMI image boots the latest HWE kernel for that week.
# This means host kernel can CHANGE between deploys, even if no Pulumi stack changes.
#
# Kernel version mismatch procedure:
# 1. `ssh ubuntu@<host> uname -r` to get the actual running kernel
# 2. Check if that version is in .github/workflows/build-release.yml matrix
# 3. If missing, add the kernel version + push tag (triggers CI build of .ko)
# 4. Ansible pre-flight check (kernel-module/tasks/main.yml) will catch the mismatch
#    and provide guidance for next steps
#
# To pin a specific kernel version: modify the AMI filter to include a date
# constraint (e.g. "ubuntu-jammy-22.04-amd64-server-20240101-*"), but this requires
# monthly maintenance as Canonical publishes new snapshots.
AMI_NAME_FILTER = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-*"

# ---------------------------------------------------------------------------
# Network constants
# ---------------------------------------------------------------------------

# VPC CIDR per relay region. Non-overlapping /16 blocks.
REGION_CIDR_MAP: dict[str, str] = {
    "us-east-1":       "10.1.0.0/16",
    "eu-west-1":       "10.2.0.0/16",
    "ap-southeast-1":  "10.3.0.0/16",
}

# Backend VPC uses us-east-1 CIDR (backend is always in us-east-1).
BACKEND_CIDR = "10.10.0.0/16"

# ---------------------------------------------------------------------------
# AZ constraints for c5n instances
# c5n is not available in all AZs. These are known-good AZs per region.
# Subnets are pinned to these AZs.
# ---------------------------------------------------------------------------
C5N_AZ_MAP: dict[str, str] = {
    "us-east-1":       "us-east-1a",
    "eu-west-1":       "eu-west-1b",
    "ap-southeast-1":  "ap-southeast-1a",
}

# Fallback AZ for regions not in C5N_AZ_MAP (e.g. backend region when
# backend_region == us-east-1 and instance is not c5n).
DEFAULT_AZ_SUFFIX = "a"


def _az_for_region(region: str) -> str:
    """Return the preferred AZ for a given region."""
    if region in C5N_AZ_MAP:
        return C5N_AZ_MAP[region]
    return region + DEFAULT_AZ_SUFFIX


# ---------------------------------------------------------------------------
# Stack config dataclass
# ---------------------------------------------------------------------------

@dataclass
class InfraConfig:
    """All stack-level config values, read once at startup."""

    # List of AWS regions to deploy relay nodes into.
    relay_regions: List[str]

    # Number of relay nodes (must match len(relay_regions) for production).
    relay_count: int

    # EC2 instance type for relay nodes.
    # Production: c5n.xlarge (ena driver, XDP native).
    # Staging:    t3.medium  (XDP generic, acceptable for testing).
    relay_instance_type: str

    # AWS region for the backend node.
    backend_region: str

    # EC2 instance type for the backend node.
    backend_instance_type: str

    # Path to local SSH public key file.
    # The public key is imported into each AWS region via aws.ec2.KeyPair.
    # The private key never leaves the local machine.
    key_pub_path: str

    # CIDR block allowed to reach SSH port 22 on all nodes AND the backend
    # admin HTTP port (P1-14). Must be set explicitly; the Pulumi config
    # placeholder REQUIRED_OVERRIDE forces this. Production additionally
    # refuses 0.0.0.0/0 (P1-04). Set to operator IP /32, e.g. "203.0.113.5/32".
    admin_cidr: str

    # Derived: preferred AZ per relay region.
    relay_azs: dict = field(init=False)

    def __post_init__(self) -> None:
        self.relay_azs = {r: _az_for_region(r) for r in self.relay_regions}
        # Also include backend region.
        self.relay_azs[self.backend_region] = _az_for_region(self.backend_region)

    @property
    def stack_name(self) -> str:
        return pulumi.get_stack()

    @property
    def public_key_text(self) -> str:
        """Read the local SSH public key file."""
        path = Path(self.key_pub_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(
                f"SSH public key not found at {path}. "
                "Set key_pub_path in Pulumi.<stack>.yaml to a valid path."
            )
        return path.read_text().strip()

    @property
    def vpc_cidr_for_region(self) -> dict[str, str]:
        """Return CIDR map for relay regions only.

        Backend CIDR is always BACKEND_CIDR and is read directly from the
        module constant in __main__.py - not through this map. This avoids
        overwriting the relay CIDR for us-east-1 when backend_region overlaps
        with a relay region (e.g. staging: both relay and backend in us-east-1).
        """
        return dict(REGION_CIDR_MAP)


def _validate_admin_cidr(admin_cidr: str, stack_name: str) -> None:
    """Refuse to proceed when admin_cidr is the placeholder or wide-open.

    P1-04 / audit v2: production must use a narrow CIDR. Staging is permitted
    to be slightly wider but must still be set explicitly (the placeholder
    REQUIRED_OVERRIDE is rejected on every stack).
    """
    if admin_cidr == "REQUIRED_OVERRIDE":
        raise pulumi.RunError(
            f"admin_cidr is unset on stack {stack_name!r}. "
            "Override with `pulumi config set admin_cidr <YOUR_IP>/32 "
            f"--stack {stack_name}` before running `pulumi up`. "
            "See P1-04 in docs/sessions/2026-05-04-project-audit-plan-v2.md."
        )
    if stack_name == "production" and admin_cidr in ("0.0.0.0/0", "::/0"):
        raise pulumi.RunError(
            f"admin_cidr={admin_cidr!r} is wide-open and refused on the "
            "production stack (P1-04). Set a narrow CIDR (e.g. your "
            "office IP /32) before running `pulumi up --stack production`."
        )


def load() -> InfraConfig:
    """Read Pulumi stack config and return an InfraConfig instance."""
    cfg = pulumi.Config()

    relay_regions: List[str] = cfg.require_object("relay_regions")
    relay_count: int = int(cfg.require("relay_count"))
    relay_instance_type: str = cfg.require("relay_instance_type")
    backend_region: str = cfg.require("backend_region")
    backend_instance_type: str = cfg.require("backend_instance_type")
    key_pub_path: str = cfg.get("key_pub_path") or "~/.ssh/id_ed25519.pub"
    # P1-04: require explicit admin_cidr - no silent default to 0.0.0.0/0.
    admin_cidr: str = cfg.require("admin_cidr")

    _validate_admin_cidr(admin_cidr, pulumi.get_stack())

    return InfraConfig(
        relay_regions=relay_regions,
        relay_count=relay_count,
        relay_instance_type=relay_instance_type,
        backend_region=backend_region,
        backend_instance_type=backend_instance_type,
        key_pub_path=key_pub_path,
        admin_cidr=admin_cidr,
    )
