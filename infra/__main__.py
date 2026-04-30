"""
__main__.py - Pulumi entrypoint for relay-xdp-infra.

Orchestrates all AWS resources across regions:
  - Production:  3x RelayNode (us-east-1, eu-west-1, ap-southeast-1)
               + 1x BackendNode (us-east-1)
  - Staging:     1x RelayNode (us-east-1)
               + 1x BackendNode (us-east-1)

Stack config is read from Pulumi.<stack>.yaml via config.load().
State is stored in the S3 backend configured at login time.

Usage:
  pulumi up --stack production
  pulumi up --stack staging
"""

from __future__ import annotations

import pulumi
import pulumi_aws as aws

import config as cfg_module
from network import create_regional_network
from relay_node import RelayNode
from backend_node import BackendNode

# ---------------------------------------------------------------------------
# Load stack config
# ---------------------------------------------------------------------------
cfg = cfg_module.load()
stack_name = cfg.stack_name
public_key_text = cfg.public_key_text
cidr_map = cfg.vpc_cidr_for_region

# ---------------------------------------------------------------------------
# Relay nodes - one per region
# ---------------------------------------------------------------------------
# Each region gets its own aws.Provider instance so all resources in that
# region are created with the correct endpoint.
relay_nodes: dict[str, RelayNode] = {}

for i, region in enumerate(cfg.relay_regions):
    node_name = f"relay-{stack_name}-{i + 1}"
    az = cfg.relay_azs[region]
    vpc_cidr = cidr_map.get(region, f"10.{i + 1}.0.0/16")

    provider = aws.Provider(
        f"aws-{region}",
        region=region,
    )

    net = create_regional_network(
        stack_name=stack_name,
        region=region,
        az=az,
        vpc_cidr=vpc_cidr,
        admin_cidr=cfg.admin_cidr,
        provider=provider,
    )

    node = RelayNode(
        node_name=node_name,
        region=region,
        az=az,
        instance_type=cfg.relay_instance_type,
        public_key_text=public_key_text,
        stack_name=stack_name,
        net=net,
        provider=provider,
    )

    relay_nodes[node_name] = node

# ---------------------------------------------------------------------------
# Backend node
# ---------------------------------------------------------------------------
backend_region = cfg.backend_region
backend_provider = aws.Provider(
    f"aws-backend-{backend_region}",
    region=backend_region,
)

backend_vpc_cidr = cfg_module.BACKEND_CIDR
backend_az = cfg.relay_azs.get(backend_region, backend_region + "a")

backend_net = create_regional_network(
    stack_name=f"{stack_name}-backend",
    region=backend_region,
    az=backend_az,
    vpc_cidr=backend_vpc_cidr,
    admin_cidr=cfg.admin_cidr,
    provider=backend_provider,
)

backend_node_name = f"backend-{stack_name}-1"
backend = BackendNode(
    node_name=backend_node_name,
    region=backend_region,
    instance_type=cfg.backend_instance_type,
    public_key_text=public_key_text,
    stack_name=stack_name,
    net=backend_net,
    provider=backend_provider,
)

# ---------------------------------------------------------------------------
# Stack exports
#
# relay_nodes: dict keyed by node name, each value has:
#   public_ip, private_ip, instance_id, region, name
#
# backend: same shape for the single backend node.
#
# These outputs are consumed by infra/inventory_gen.py to render
# ansible/inventory/<stack>.yml.
# ---------------------------------------------------------------------------
pulumi.export(
    "relay_nodes",
    pulumi.Output.all(
        **{
            name: pulumi.Output.all(
                public_ip=node.public_ip,
                private_ip=node.private_ip,
                instance_id=node.instance_id,
                region=node.region,
                name=node.name,
            )
            for name, node in relay_nodes.items()
        }
    ),
)

pulumi.export(
    "backend",
    pulumi.Output.all(
        public_ip=backend.public_ip,
        private_ip=backend.private_ip,
        instance_id=backend.instance_id,
        region=backend.region,
        name=backend.name,
    ),
)

pulumi.export("stack", stack_name)

