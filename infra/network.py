"""
network.py - Per-region VPC, subnet, Internet Gateway, route table, and
security groups for relay-xdp infrastructure.

Each relay region gets an independent VPC. There is no VPC Peering between
regions - relay-to-relay UDP traffic flows over the public internet via EIPs.
"""

from __future__ import annotations

from dataclasses import dataclass

import pulumi
import pulumi_aws as aws


@dataclass
class NetworkResult:
    """Outputs from create_regional_network()."""
    vpc: aws.ec2.Vpc
    subnet: aws.ec2.Subnet
    sg_relay: aws.ec2.SecurityGroup
    sg_backend: aws.ec2.SecurityGroup


def create_regional_network(
    stack_name: str,
    region: str,
    vpc_cidr: str,
    admin_cidr: str,
    provider: aws.Provider,
) -> NetworkResult:
    """
    Create networking resources for one AWS region.

    Resources created:
      - VPC with DNS support enabled
      - Public subnet (pinned to AZ from caller)
      - Internet Gateway + Route Table + Association
      - sg_relay:   UDP 40000 open, TCP 8080 open, TCP 22 from admin_cidr
      - sg_backend: TCP 8090 open, TCP 6379 from VPC only, TCP 22 from admin_cidr

    Parameters
    ----------
    stack_name:  Pulumi stack name (e.g. "production"), used in resource names.
    region:      AWS region string (e.g. "us-east-1").
    vpc_cidr:    VPC IPv4 CIDR block (e.g. "10.1.0.0/16").
    admin_cidr:  CIDR allowed to reach SSH port 22 (e.g. "203.0.113.5/32").
    provider:    Regional aws.Provider instance.
    """
    opts = pulumi.ResourceOptions(provider=provider)
    name = f"{stack_name}-{region}"

    # ------------------------------------------------------------------
    # VPC
    # ------------------------------------------------------------------
    vpc = aws.ec2.Vpc(
        f"vpc-{name}",
        cidr_block=vpc_cidr,
        enable_dns_hostnames=True,
        enable_dns_support=True,
        tags={"Name": f"relay-{name}", "Stack": stack_name, "Region": region},
        opts=opts,
    )

    # ------------------------------------------------------------------
    # Internet Gateway
    # ------------------------------------------------------------------
    igw = aws.ec2.InternetGateway(
        f"igw-{name}",
        vpc_id=vpc.id,
        tags={"Name": f"relay-igw-{name}", "Stack": stack_name},
        opts=opts,
    )

    # ------------------------------------------------------------------
    # Public subnet - uses first /24 of the VPC CIDR.
    # AZ is passed in via the subnet_cidr parameter from the caller
    # (relay_node / backend_node), so the subnet CIDR is derived here
    # as the .0.0/24 of the VPC block.
    # ------------------------------------------------------------------
    # Derive subnet CIDR: replace last two octets with 0.0/24.
    # e.g. "10.1.0.0/16" -> "10.1.0.0/24"
    subnet_cidr = vpc_cidr.rsplit(".", 2)[0] + ".0.0/24"

    subnet = aws.ec2.Subnet(
        f"subnet-{name}",
        vpc_id=vpc.id,
        cidr_block=subnet_cidr,
        map_public_ip_on_launch=True,
        tags={"Name": f"relay-subnet-{name}", "Stack": stack_name},
        opts=opts,
    )

    # ------------------------------------------------------------------
    # Route table - default route via IGW
    # ------------------------------------------------------------------
    rt = aws.ec2.RouteTable(
        f"rt-{name}",
        vpc_id=vpc.id,
        routes=[
            aws.ec2.RouteTableRouteArgs(
                cidr_block="0.0.0.0/0",
                gateway_id=igw.id,
            )
        ],
        tags={"Name": f"relay-rt-{name}", "Stack": stack_name},
        opts=opts,
    )

    aws.ec2.RouteTableAssociation(
        f"rt-assoc-{name}",
        subnet_id=subnet.id,
        route_table_id=rt.id,
        opts=opts,
    )

    # ------------------------------------------------------------------
    # Security Group: relay nodes
    #   - UDP 40000 open to internet (game clients + inter-relay ping/pong)
    #   - TCP 8080 open to internet (relay HTTP health endpoint)
    #   - TCP 22   from admin_cidr only
    #   - All outbound allowed
    # ------------------------------------------------------------------
    sg_relay = aws.ec2.SecurityGroup(
        f"sg-relay-{name}",
        vpc_id=vpc.id,
        description="relay-xdp relay node security group",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                description="Relay UDP (game clients + inter-relay ping)",
                protocol="udp",
                from_port=40000,
                to_port=40000,
                cidr_blocks=["0.0.0.0/0"],
                ipv6_cidr_blocks=["::/0"],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="Relay HTTP health endpoint",
                protocol="tcp",
                from_port=8080,
                to_port=8080,
                cidr_blocks=["0.0.0.0/0"],
                ipv6_cidr_blocks=["::/0"],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="SSH admin access",
                protocol="tcp",
                from_port=22,
                to_port=22,
                cidr_blocks=[admin_cidr],
            ),
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                description="All outbound",
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
                ipv6_cidr_blocks=["::/0"],
            )
        ],
        tags={"Name": f"relay-sg-relay-{name}", "Stack": stack_name},
        opts=opts,
    )

    # ------------------------------------------------------------------
    # Security Group: backend node
    #   - TCP 8090 open to internet (relay nodes POST /relay_update)
    #   - TCP 6379 from VPC CIDR only (Redis - never expose to internet)
    #   - TCP 22   from admin_cidr only
    #   - All outbound allowed
    # ------------------------------------------------------------------
    sg_backend = aws.ec2.SecurityGroup(
        f"sg-backend-{name}",
        vpc_id=vpc.id,
        description="relay-xdp backend node security group",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                description="Backend HTTP (/relay_update, /route_matrix)",
                protocol="tcp",
                from_port=8090,
                to_port=8090,
                cidr_blocks=["0.0.0.0/0"],
                ipv6_cidr_blocks=["::/0"],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="Redis - internal VPC only",
                protocol="tcp",
                from_port=6379,
                to_port=6379,
                cidr_blocks=[vpc_cidr],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="SSH admin access",
                protocol="tcp",
                from_port=22,
                to_port=22,
                cidr_blocks=[admin_cidr],
            ),
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                description="All outbound",
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
                ipv6_cidr_blocks=["::/0"],
            )
        ],
        tags={"Name": f"relay-sg-backend-{name}", "Stack": stack_name},
        opts=opts,
    )

    return NetworkResult(
        vpc=vpc,
        subnet=subnet,
        sg_relay=sg_relay,
        sg_backend=sg_backend,
    )

