"""
backend_node.py - BackendNode ComponentResource.

Provisions one relay-backend EC2 instance:
  - relay-backend (tokio + axum) on TCP 8090
  - Redis on TCP 6379, accessible from VPC only (Redis never exposed publicly)
  - Elastic IP: stable public address used as RELAY_BACKEND_URL on relay nodes.
    Without an EIP the auto-assigned public IP changes on every stop/start, which
    would invalidate the Ansible inventory and break relay -> backend HTTP POSTs.

Instance type:
  Production: c5.large
  Staging:    t3.medium
"""

from __future__ import annotations

from textwrap import dedent

import pulumi
import pulumi_aws as aws

from config import CANONICAL_OWNER_ID, AMI_NAME_FILTER
from network import NetworkResult


_USER_DATA = dedent("""\
    #!/bin/bash
    set -euo pipefail

    # Wait for apt lock
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done

    apt-get update -qq
    apt-get install -y libelf1 redis-server

    # Bind Redis to localhost only - security hardening.
    # relay-backend connects via 127.0.0.1:6379.
    sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf
    systemctl enable redis-server
    systemctl start redis-server
""")


class BackendNode(pulumi.ComponentResource):
    """
    One relay-backend EC2 instance.

    Outputs:
      public_ip   - Elastic IP address (stable across instance stops/starts)
      private_ip  - Instance private IP within the VPC
      instance_id - EC2 instance ID
      region      - AWS region string
      name        - Logical node name (e.g. "backend-production-1")
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
        net: NetworkResult,
        provider: aws.Provider,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        """
        Parameters
        ----------
        node_name:        Logical name, e.g. "backend-production-1".
        region:           AWS region string.
        instance_type:    EC2 instance type, e.g. "c5.large".
        public_key_text:  Contents of ~/.ssh/id_ed25519.pub.
        stack_name:       Pulumi stack name.
        net:              NetworkResult from create_regional_network().
        provider:         Regional aws.Provider.
        opts:             Optional Pulumi resource options.
        """
        super().__init__("relay-xdp:infra:BackendNode", node_name, {}, opts)

        child_opts = pulumi.ResourceOptions(provider=provider, parent=self)

        # ------------------------------------------------------------------
        # SSH key pair - same local public key, imported into backend region.
        # ------------------------------------------------------------------
        key_pair = aws.ec2.KeyPair(
            f"keypair-{node_name}",
            public_key=public_key_text,
            key_name=f"relay-backend-{stack_name}",
            tags={"Name": f"relay-backend-{stack_name}", "Stack": stack_name},
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # AMI lookup
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
        # EC2 instance
        # associate_public_ip_address is False - the Elastic IP below provides
        # the stable public address. Relying on the auto-assigned ephemeral IP
        # would cause SSH timeouts and broken RELAY_BACKEND_URL after any stop/start.
        # ------------------------------------------------------------------
        instance = aws.ec2.Instance(
            f"instance-{node_name}",
            ami=ami.id,
            instance_type=instance_type,
            subnet_id=net.subnet.id,
            vpc_security_group_ids=[net.sg_backend.id],
            key_name=key_pair.key_name,
            associate_public_ip_address=False,
            user_data=_USER_DATA,
            user_data_replace_on_change=False,
            root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(
                volume_type="gp3",
                volume_size=20,
                delete_on_termination=True,
            ),
            tags={
                "Name":   node_name,
                "Stack":  stack_name,
                "Region": region,
                "Role":   "backend",
            },
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # Elastic IP - stable public address for Ansible SSH and
        # RELAY_BACKEND_URL used by relay nodes. Without this the auto-assigned
        # IP changes on every instance stop/start, invalidating the inventory.
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

