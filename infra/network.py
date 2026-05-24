"""
network.py - Per-region VPC, subnet, Internet Gateway, route table, and
security groups for relay-xdp infrastructure.

Each relay region gets an independent VPC. There is no VPC Peering between
regions - relay-to-relay UDP traffic flows over the public internet via EIPs.

Two public API functions:
  create_relay_network()   - Used by relay regions. Creates sg_relay only.
  create_backend_network() - Used by the backend region. Creates sg_backend + sg_bench.

Both share the _create_vpc_base() private helper for VPC/subnet/IGW/RT creation.
"""

from __future__ import annotations

from dataclasses import dataclass

import pulumi
import pulumi_aws as aws


@dataclass
class RelayNetworkResult:
    """Outputs from create_relay_network()."""
    vpc: aws.ec2.Vpc
    subnet: aws.ec2.Subnet
    sg_relay: aws.ec2.SecurityGroup


@dataclass
class BackendNetworkResult:
    """Outputs from create_backend_network()."""
    vpc: aws.ec2.Vpc
    subnet: aws.ec2.Subnet
    sg_backend: aws.ec2.SecurityGroup
    sg_bench: aws.ec2.SecurityGroup


def _create_vpc_base(
    name: str,
    stack_name: str,
    region: str,
    az: str,
    vpc_cidr: str,
    opts: pulumi.ResourceOptions,
) -> tuple[aws.ec2.Vpc, aws.ec2.Subnet]:
    """
    Create the shared VPC skeleton: VPC, IGW, public subnet, route table.

    Returns (vpc, subnet). Called by both create_relay_network() and
    create_backend_network() - DRY base for the two variants.
    """
    vpc = aws.ec2.Vpc(
        f"vpc-{name}",
        cidr_block=vpc_cidr,
        enable_dns_hostnames=True,
        enable_dns_support=True,
        tags={"Name": f"relay-{name}", "Stack": stack_name, "Region": region},
        opts=opts,
    )

    igw = aws.ec2.InternetGateway(
        f"igw-{name}",
        vpc_id=vpc.id,
        tags={"Name": f"relay-igw-{name}", "Stack": stack_name},
        opts=opts,
    )

    # Derive subnet CIDR: replace last two octets with 0.0/24.
    # e.g. "10.1.0.0/16" -> "10.1.0.0/24"
    subnet_cidr = vpc_cidr.rsplit(".", 2)[0] + ".0.0/24"

    subnet = aws.ec2.Subnet(
        f"subnet-{name}",
        vpc_id=vpc.id,
        cidr_block=subnet_cidr,
        availability_zone=az,
        map_public_ip_on_launch=True,
        tags={"Name": f"relay-subnet-{name}", "Stack": stack_name},
        opts=opts,
    )

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

    return vpc, subnet


def create_relay_network(
    stack_name: str,
    region: str,
    az: str,
    vpc_cidr: str,
    admin_cidr: str,
    provider: aws.Provider,
) -> RelayNetworkResult:
    """
    Create networking resources for one relay AWS region.

    Resources created:
      - VPC with DNS support enabled
      - Public subnet (pinned to az)
      - Internet Gateway + Route Table + Association
      - sg_relay: UDP 40000 open, TCP 8080 open, TCP 22 from admin_cidr

    Parameters
    ----------
    stack_name:  Pulumi stack name (e.g. "production"), used in resource names.
    region:      AWS region string (e.g. "us-east-1").
    az:          Availability zone to pin the subnet to (e.g. "us-east-1a").
                  Must support the intended instance type. c5n and c6in require
                  specific AZs - see config.py:RELAY_AZ_MAP.
    vpc_cidr:    VPC IPv4 CIDR block (e.g. "10.1.0.0/16").
    admin_cidr:  CIDR allowed to reach SSH port 22 (e.g. "203.0.113.5/32").
    provider:    Regional aws.Provider instance.
    """
    opts = pulumi.ResourceOptions(provider=provider)
    name = f"{stack_name}-{region}"

    vpc, subnet = _create_vpc_base(name, stack_name, region, az, vpc_cidr, opts)

    # ------------------------------------------------------------------
    # Security Group: relay nodes
    #   - UDP 40000 open to internet (game clients + inter-relay ping/pong)
    #   - TCP 8080 open to internet (relay HTTP health endpoint)
    #   - TCP 22   from admin_cidr only
    #   - All outbound allowed
    # ------------------------------------------------------------------
    sg_relay = aws.ec2.SecurityGroup(
        f"sg-relay-{name}",
        name=f"relay-node-{name}",
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

    return RelayNetworkResult(vpc=vpc, subnet=subnet, sg_relay=sg_relay)


def create_backend_network(
    stack_name: str,
    region: str,
    az: str,
    vpc_cidr: str,
    admin_cidr: str,
    provider: aws.Provider,
) -> BackendNetworkResult:
    """
    Create networking resources for the backend AWS region.

    Resources created:
      - VPC with DNS support enabled
      - Public subnet (pinned to az)
      - Internet Gateway + Route Table + Association
      - sg_backend: TCP 8090/8091/8180 open, TCP 6379 from VPC, TCP 22 from admin_cidr
      - sg_bench:   TCP 18080 from admin_cidr + VPC, UDP 17777 open, TCP 22 from admin_cidr

    Parameters
    ----------
    stack_name:  Pulumi stack name (e.g. "production"), used in resource names.
    region:      AWS region string (e.g. "us-east-1").
    az:          Availability zone to pin the subnet to.
    vpc_cidr:    VPC IPv4 CIDR block (e.g. "10.10.0.0/16").
    admin_cidr:  CIDR allowed to reach SSH port 22 (e.g. "203.0.113.5/32").
    provider:    Regional aws.Provider instance.
    """
    opts = pulumi.ResourceOptions(provider=provider)
    name = f"{stack_name}-{region}"

    vpc, subnet = _create_vpc_base(name, stack_name, region, az, vpc_cidr, opts)

    # ------------------------------------------------------------------
    # Security Group: backend node
    #   - TCP 8090 open to internet (relay nodes POST /relay_update + health)
    #   - TCP 8091 from admin_cidr only (admin / data plane: cost matrix,
    #     route matrix, /metrics, /relays, /relay_counters - see audit P1-14)
    #   - TCP 8180 open to internet (server-backend matchmaking API)
    #   - TCP 6379 from VPC CIDR only (Redis - never expose to internet)
    #   - TCP 22   from admin_cidr only
    #   - All outbound allowed
    # ------------------------------------------------------------------
    sg_backend = aws.ec2.SecurityGroup(
        f"sg-backend-{name}",
        name=f"backend-node-{name}",
        vpc_id=vpc.id,
        description="relay-xdp backend node security group",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                description="Backend public HTTP (/relay_update + health)",
                protocol="tcp",
                from_port=8090,
                to_port=8090,
                cidr_blocks=["0.0.0.0/0"],
                ipv6_cidr_blocks=["::/0"],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="Backend admin HTTP (topology, /metrics) - admin_cidr only",
                protocol="tcp",
                from_port=8091,
                to_port=8091,
                cidr_blocks=[admin_cidr],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="server-backend matchmaking API - public",
                protocol="tcp",
                from_port=8180,
                to_port=8180,
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

    # ------------------------------------------------------------------
    # Security Group: bench node (game server simulator)
    #   - TCP 18080 from admin_cidr only (bench_client POST /register_session,
    #     direct/relay mode) AND from vpc_cidr (server-backend POST /notify_session
    #     webhook - server-backend is on backend_node, same VPC as bench_node)
    #   - UDP 17777 open to internet (relay-xdp forwards CLIENT_TO_SERVER here)
    #   - TCP 22    from admin_cidr only
    # ------------------------------------------------------------------
    sg_bench = aws.ec2.SecurityGroup(
        f"sg-bench-{name}",
        name=f"bench-node-{name}",
        vpc_id=vpc.id,
        description="bench_server game server simulator security group",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                description="bench_server HTTP provisioning (admin only)",
                protocol="tcp",
                from_port=18080,
                to_port=18080,
                cidr_blocks=[admin_cidr],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="bench_server HTTP webhook from server-backend (VPC internal)",
                protocol="tcp",
                from_port=18080,
                to_port=18080,
                cidr_blocks=[vpc_cidr],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                description="bench_server UDP echo (relay-xdp forwards here)",
                protocol="udp",
                from_port=17777,
                to_port=17777,
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
        tags={"Name": f"relay-sg-bench-{name}", "Stack": stack_name},
        opts=opts,
    )

    return BackendNetworkResult(
        vpc=vpc,
        subnet=subnet,
        sg_backend=sg_backend,
        sg_bench=sg_bench,
    )

