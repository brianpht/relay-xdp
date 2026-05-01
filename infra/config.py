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

# Ubuntu 22.04 LTS (Jammy) x86_64 HWE kernel on GP3 SSD.
# HWE (Hardware Enablement) kernel auto-updates to latest stable (currently 6.17).
# Kernel 6.17 meets the >=6.5 requirement for BTF and kfunc support.
#
# CI matrix (build-release.yml) must include all HWE kernel versions deployed
# on staging/production hosts, since new AMI images may boot different kernels.
# When deploying to a new host, verify `uname -r` and ensure the kernel is
# in the CI matrix before running ansible-playbook.
AMI_NAME_FILTER = "ubuntu/images/hvm-ssd-gp3/ubuntu-jammy-22.04-amd64-server-*"

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

    # CIDR block allowed to reach SSH port 22 on all nodes.
    # Should be set to your operator IP in production, e.g. "203.0.113.5/32".
    # Defaults to 0.0.0.0/0 (open) - override before first deploy.
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


def load() -> InfraConfig:
    """Read Pulumi stack config and return an InfraConfig instance."""
    cfg = pulumi.Config()

    relay_regions: List[str] = cfg.require_object("relay_regions")
    relay_count: int = int(cfg.require("relay_count"))
    relay_instance_type: str = cfg.require("relay_instance_type")
    backend_region: str = cfg.require("backend_region")
    backend_instance_type: str = cfg.require("backend_instance_type")
    key_pub_path: str = cfg.get("key_pub_path") or "~/.ssh/id_ed25519.pub"
    admin_cidr: str = cfg.get("admin_cidr") or "0.0.0.0/0"

    return InfraConfig(
        relay_regions=relay_regions,
        relay_count=relay_count,
        relay_instance_type=relay_instance_type,
        backend_region=backend_region,
        backend_instance_type=backend_instance_type,
        key_pub_path=key_pub_path,
        admin_cidr=admin_cidr,
    )

