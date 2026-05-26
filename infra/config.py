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

# Ubuntu 24.04 LTS (Noble Numbat) x86_64 HWE kernel on EBS gp3 SSD.
#
# Ubuntu 24.04 LTS support: Until April 2034 (5-year baseline + 5-year extended).
# HWE (Hardware Enablement) kernel: auto-updates to latest stable (currently 6.11+).
# Kernel requirement: >=6.5 for BTF and kfunc support (XDP kernel module).
#
# Path change from Jammy: Canonical switched Noble images to the hvm-ssd-gp3 path.
# Do NOT use the old hvm-ssd path for Noble - it will return no results.
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
# constraint (e.g. "ubuntu-noble-24.04-amd64-server-20240101-*"), but this requires
# monthly maintenance as Canonical publishes new snapshots.
AMI_NAME_FILTER = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-*"

# ---------------------------------------------------------------------------
# Network constants
# ---------------------------------------------------------------------------

# VPC CIDR per region. Non-overlapping /16 blocks.
# All supported relay regions are listed explicitly - adding a new region
# requires an entry here. No fallback is provided; missing entries raise
# pulumi.RunError at deploy time to prevent silent CIDR reassignment.
REGION_CIDR_MAP: dict[str, str] = {
    "us-east-1":       "10.1.0.0/16",
    "eu-west-1":       "10.2.0.0/16",
    "ap-southeast-1":  "10.3.0.0/16",
    "ap-northeast-1":  "10.4.0.0/16",
    "eu-central-1":    "10.5.0.0/16",
    "us-west-2":       "10.6.0.0/16",
    "sa-east-1":       "10.7.0.0/16",
    "ap-south-1":      "10.8.0.0/16",
    "ca-central-1":    "10.9.0.0/16",
}

# Backend VPC uses us-east-1 CIDR (backend is always in us-east-1).
BACKEND_CIDR = "10.10.0.0/16"

# ---------------------------------------------------------------------------
# AZ constraints for relay instance types (c5n.2xlarge, c6in.8xlarge).
# Neither c5n nor c6in is available in all AZs within a region.
# These are known-good AZs verified for both instance families.
# Subnets are pinned to these AZs.
#
# Adding a new region requires an explicit entry here. After expanding this map
# to cover all supported regions the fallback is removed - a missing entry raises
# ValueError in InfraConfig.__post_init__ so misconfigured deployments fail fast.
# ---------------------------------------------------------------------------
RELAY_AZ_MAP: dict[str, str] = {
    "us-east-1":       "us-east-1a",
    "eu-west-1":       "eu-west-1b",
    "ap-southeast-1":  "ap-southeast-1a",
    "ap-northeast-1":  "ap-northeast-1a",
    "eu-central-1":    "eu-central-1a",
    "us-west-2":       "us-west-2b",
    "sa-east-1":       "sa-east-1a",
    "ap-south-1":      "ap-south-1a",
    "ca-central-1":    "ca-central-1a",
}

# Geographic center coordinates per AWS region (latitude, longitude).
# Used by relay-backend to compute distance-based route cost matrix.
# Values are the approximate datacenter campus coordinates.
REGION_LATLONG_MAP: dict[str, tuple[float, float]] = {
    "us-east-1":       (39.04,  -77.49),   # N. Virginia
    "eu-west-1":       (53.33,   -6.25),   # Ireland
    "ap-southeast-1":  ( 1.35,  103.82),   # Singapore
    "ap-northeast-1":  (35.68,  139.69),   # Tokyo
    "eu-central-1":    (50.11,    8.68),   # Frankfurt
    "us-west-2":       (45.52, -122.68),   # Oregon
    "sa-east-1":       (-23.55, -46.63),   # Sao Paulo
    "ap-south-1":      (19.08,   72.88),   # Mumbai
    "ca-central-1":    (45.53,  -73.55),   # Montreal
}


# ---------------------------------------------------------------------------
# Stack config dataclass
# ---------------------------------------------------------------------------

@dataclass
class InfraConfig:
    """All stack-level config values, read once at startup."""

    # List of AWS regions to deploy relay nodes into.
    relay_regions: List[str]

    # EC2 instance type for relay nodes.
    # Production: c6in.8xlarge (ena driver, XDP native, high network bandwidth).
    # Staging:    c5n.2xlarge  (ena driver, XDP native - same code path as production).
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
    # Must be set to your operator IP, e.g. "203.0.113.5/32".
    # There is no default - deploy will fail at the Makefile preflight
    # check if this is left as the REPLACE_ME placeholder.
    admin_cidr: str

    # Optional bench node (game server simulator for relay-mode benchmarks).
    # Set bench_enabled: "true" in Pulumi.<stack>.yaml to provision.
    # Never set in production - bench node is staging/dev only.
    bench_enabled: bool = False
    bench_instance_type: str = "t3.micro"

    # Derived: preferred AZ per relay region (and backend region).
    relay_azs: dict = field(init=False)

    def __post_init__(self) -> None:
        for r in self.relay_regions:
            if r not in RELAY_AZ_MAP:
                raise ValueError(
                    f"Relay region '{r}' has no entry in RELAY_AZ_MAP. "
                    "Add an explicit AZ entry in infra/config.py before deploying."
                )
        if self.backend_region not in RELAY_AZ_MAP:
            raise ValueError(
                f"backend_region '{self.backend_region}' has no entry in RELAY_AZ_MAP. "
                "Add an explicit AZ entry in infra/config.py before deploying."
            )
        self.relay_azs = {r: RELAY_AZ_MAP[r] for r in self.relay_regions}
        self.relay_azs[self.backend_region] = RELAY_AZ_MAP[self.backend_region]

    @property
    def relay_count(self) -> int:
        """Derived relay node count - always equals len(relay_regions)."""
        return len(self.relay_regions)

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


def _validate_admin_cidr(cidr: str, stack: str) -> None:
    """Reject unsafe admin_cidr values before any AWS resource is created.

    Rules:
    - Any placeholder value (REQUIRED_OVERRIDE, REPLACE_ME) is always rejected
      regardless of stack, to force an explicit operator choice.
    - 0.0.0.0/0 and ::/0 are rejected on production (SSH open to the world).
    - 0.0.0.0/0 is allowed on staging as a conscious operator choice after the
      placeholder has been cleared; a warning is logged instead.
    - Bare IPv6 addresses (containing ':') used as an IPv4 CIDR are always
      rejected; EC2 security group cidr_blocks only accepts IPv4 notation.
    """
    import ipaddress

    _PLACEHOLDERS = ("REQUIRED_OVERRIDE", "REPLACE_ME")
    for placeholder in _PLACEHOLDERS:
        if placeholder in cidr:
            raise pulumi.RunError(
                f"admin_cidr '{cidr}' still contains placeholder '{placeholder}'. "
                "Set your operator CIDR with: "
                "pulumi config set relay-xdp-infra:admin_cidr \"$(curl -4 -s ifconfig.me)/32\""
            )

    # Reject IPv6 addresses used where an IPv4 CIDR is expected.
    # EC2 SecurityGroup cidr_blocks only accepts IPv4; ipv6_cidr_blocks is separate.
    if ":" in cidr:
        raise pulumi.RunError(
            f"admin_cidr '{cidr}' looks like an IPv6 address. "
            "EC2 security group cidr_blocks requires IPv4 notation. "
            "Use: pulumi config set relay-xdp-infra:admin_cidr \"$(curl -4 -s ifconfig.me)/32\""
        )

    # Validate it is actually a parseable CIDR block.
    try:
        ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise pulumi.RunError(
            f"admin_cidr '{cidr}' is not a valid IPv4 CIDR block: {exc}. "
            "Example: \"203.0.113.5/32\""
        ) from exc

    _WIDE_OPEN = ("0.0.0.0/0", "::/0")
    if stack == "production" and cidr in _WIDE_OPEN:
        raise pulumi.RunError(
            f"admin_cidr '{cidr}' opens SSH to the entire Internet on production. "
            "Set your operator CIDR with: "
            "pulumi config set relay-xdp-infra:admin_cidr \"$(curl -4 -s ifconfig.me)/32\" --stack production"
        )

    if cidr in _WIDE_OPEN:
        pulumi.log.warn(
            f"admin_cidr is '{cidr}' - SSH port 22 is open to the entire Internet. "
            "This is allowed on staging but set a real CIDR for production."
        )


def load() -> InfraConfig:
    """Read Pulumi stack config and return an InfraConfig instance."""
    cfg = pulumi.Config()

    relay_regions: List[str] = cfg.require_object("relay_regions")
    relay_instance_type: str = cfg.require("relay_instance_type")
    backend_region: str = cfg.require("backend_region")
    backend_instance_type: str = cfg.require("backend_instance_type")
    key_pub_path: str = cfg.get("key_pub_path") or "~/.ssh/id_ed25519.pub"
    admin_cidr: str = cfg.require("admin_cidr")
    bench_enabled: bool = cfg.get_bool("bench_enabled") or False
    bench_instance_type: str = cfg.get("bench_instance_type") or "t3.micro"
    _validate_admin_cidr(admin_cidr, pulumi.get_stack())

    return InfraConfig(
        relay_regions=relay_regions,
        relay_instance_type=relay_instance_type,
        backend_region=backend_region,
        backend_instance_type=backend_instance_type,
        key_pub_path=key_pub_path,
        admin_cidr=admin_cidr,
        bench_enabled=bench_enabled,
        bench_instance_type=bench_instance_type,
    )
