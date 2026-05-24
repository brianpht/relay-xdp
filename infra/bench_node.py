"""
bench_node.py - BenchNode ComponentResource.

Provisions one bench_server EC2 instance simulating a game server:
  - bench_server (relay-bench) on TCP 18080 (HTTP) + UDP 17777 (echo)
  - t3.micro: sufficient for < 10K PPS benchmark loads (~$8/month)
  - Elastic IP: stable address across stop/start cycles

Relay-mode traffic flow:
  bench_client -> relay-xdp:40000 -> bench_server:17777 -> relay-xdp -> bench_client

Role: staging only. Never provision in production (bench_enabled defaults to False).
"""

from __future__ import annotations

from textwrap import dedent

import pulumi
import pulumi_aws as aws

from config import CANONICAL_OWNER_ID, AMI_NAME_FILTER
from network import BackendNetworkResult


_USER_DATA = dedent("""\
    #!/bin/bash
    set -euo pipefail
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done
    apt-get update -qq
""")


class BenchNode(pulumi.ComponentResource):
    """
    One bench_server EC2 instance (game server simulator).

    Outputs:
      public_ip   - Elastic IP (stable across stop/start)
      private_ip  - VPC private IP
      instance_id - EC2 instance ID
      region      - AWS region string
      name        - Logical name (e.g. "bench-staging-1")
    """

    public_ip: pulumi.Output[str]
    private_ip: pulumi.Output[str]
    instance_id: pulumi.Output[str]
    region: pulumi.Output[str]
    name: pulumi.Output[str]

    def __init__(
        self,
        node_name: str,
        region: str,
        instance_type: str,
        public_key_text: str,
        stack_name: str,
        net: BackendNetworkResult,
        provider: aws.Provider,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """
        Parameters
        ----------
        node_name:        Logical name, e.g. "bench-staging-1".
        region:           AWS region string.
        instance_type:    EC2 instance type, e.g. "t3.micro".
        public_key_text:  Contents of ~/.ssh/id_ed25519.pub.
        stack_name:       Pulumi stack name.
        net:              BackendNetworkResult from create_backend_network().
                          Uses net.sg_bench - must be the backend_net result
                          since bench node is co-located in the backend region.
        provider:         Regional aws.Provider.
        opts:             Optional Pulumi resource options.
        """
        super().__init__("relay-xdp:infra:BenchNode", node_name, {}, opts)

        child_opts = pulumi.ResourceOptions(provider=provider, parent=self)

        # ------------------------------------------------------------------
        # SSH key pair
        # ------------------------------------------------------------------
        key_pair = aws.ec2.KeyPair(
            f"keypair-{node_name}",
            public_key=public_key_text,
            key_name=f"relay-bench-{stack_name}",
            tags={"Name": f"relay-bench-{stack_name}", "Stack": stack_name},
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # AMI lookup - Ubuntu 24.04 LTS (same as all other nodes)
        # ------------------------------------------------------------------
        ami = aws.ec2.get_ami(
            owners=[CANONICAL_OWNER_ID],
            most_recent=True,
            filters=[
                aws.ec2.GetAmiFilterArgs(name="name",         values=[AMI_NAME_FILTER]),
                aws.ec2.GetAmiFilterArgs(name="architecture", values=["x86_64"]),
                aws.ec2.GetAmiFilterArgs(name="state",        values=["available"]),
            ],
            opts=pulumi.InvokeOptions(provider=provider),
        )

        # ------------------------------------------------------------------
        # EC2 instance - associate_public_ip_address=False; EIP provides
        # the stable public address (same pattern as BackendNode).
        # ------------------------------------------------------------------
        instance = aws.ec2.Instance(
            f"instance-{node_name}",
            ami=ami.id,
            instance_type=instance_type,
            subnet_id=net.subnet.id,
            vpc_security_group_ids=[net.sg_bench.id],
            key_name=key_pair.key_name,
            associate_public_ip_address=False,
            user_data=_USER_DATA,
            user_data_replace_on_change=False,
            root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(
                volume_type="gp3",
                volume_size=8,
                delete_on_termination=True,
            ),
            tags={
                "Name":   node_name,
                "Stack":  stack_name,
                "Region": region,
                "Role":   "bench",
            },
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # Elastic IP - stable public address for Ansible SSH and
        # BENCH_SERVER_HTTP / BENCH_SERVER_UDP env vars used by bench_client.
        # ------------------------------------------------------------------
        eip = aws.ec2.Eip(
            f"eip-{node_name}",
            domain="vpc",
            tags={
                "Name":  f"eip-{node_name}",
                "Stack": stack_name,
            },
            opts=child_opts,
        )

        aws.ec2.EipAssociation(
            f"eip-assoc-{node_name}",
            instance_id=instance.id,
            allocation_id=eip.id,
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # Register component outputs
        # ------------------------------------------------------------------
        self.public_ip   = eip.public_ip
        self.private_ip  = instance.private_ip
        self.instance_id = instance.id
        self.region      = pulumi.Output.from_input(region)
        self.name        = pulumi.Output.from_input(node_name)

        self.register_outputs({
            "public_ip":   self.public_ip,
            "private_ip":  self.private_ip,
            "instance_id": self.instance_id,
            "region":      self.region,
            "name":        self.name,
        })

