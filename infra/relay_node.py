"""
relay_node.py - RelayNode ComponentResource.

Provisions one relay-xdp EC2 instance in a given AWS region:
  - Looks up the latest Ubuntu 24.04 x86_64 AMI (kernel 6.8, satisfies >=6.5)
  - Imports the local SSH public key into the region
  - Creates the EC2 instance with cloud-init user_data (prerequisites only)
  - Attaches an Elastic IP for a stable public address (required for game
    clients and inter-relay ping to reference a fixed endpoint)

Instance type:
  Production: c5n.xlarge - ena driver supports XDP native mode (driver-level).
  Staging:    t3.medium  - XDP generic mode, acceptable for testing.
"""

from __future__ import annotations

from textwrap import dedent

import pulumi
import pulumi_aws as aws

from config import CANONICAL_OWNER_ID, AMI_NAME_FILTER
from network import NetworkResult


# cloud-init user_data script applied to every relay node.
# Scope: install prerequisites and set sysctl for high-throughput UDP.
# Ansible common role re-applies sysctl idempotently - no conflict.
_USER_DATA = dedent("""\
    #!/bin/bash
    set -euo pipefail

    # Wait for apt lock
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done

    apt-get update -qq
    apt-get install -y libelf1 kmod

    # High-throughput UDP sysctl - mirrors ansible/roles/common/tasks/main.yml
    sysctl -w net.core.rmem_max=134217728
    sysctl -w net.core.wmem_max=134217728
    sysctl -w net.core.rmem_default=16777216
    sysctl -w net.core.wmem_default=16777216
    sysctl -w net.core.netdev_max_backlog=250000
    sysctl -w net.ipv4.udp_mem="102400 873800 134217728"

    # Persist across reboots
    cat >> /etc/sysctl.d/99-relay.conf <<'EOF'
    net.core.rmem_max=134217728
    net.core.wmem_max=134217728
    net.core.rmem_default=16777216
    net.core.wmem_default=16777216
    net.core.netdev_max_backlog=250000
    net.ipv4.udp_mem=102400 873800 134217728
    EOF
""")


class RelayNode(pulumi.ComponentResource):
    """
    One relay-xdp EC2 instance in a specific AWS region.

    Outputs (accessible as .public_ip, .private_ip, .instance_id, .region):
      public_ip   - Elastic IP address (stable, used in RELAY_PUBLIC_ADDRESS)
      private_ip  - Instance private IP within the VPC
      instance_id - EC2 instance ID
      region      - AWS region string
      name        - Logical node name (e.g. "relay-production-1")
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
        az: str,
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
        node_name:        Logical name, e.g. "relay-production-1".
        region:           AWS region string.
        az:               Availability zone (must support the instance type).
        instance_type:    EC2 instance type, e.g. "c5n.xlarge".
        public_key_text:  Contents of ~/.ssh/id_ed25519.pub.
        stack_name:       Pulumi stack name.
        net:              NetworkResult from create_regional_network().
        provider:         Regional aws.Provider.
        opts:             Optional Pulumi resource options.
        """
        super().__init__("relay-xdp:infra:RelayNode", node_name, {}, opts)

        child_opts = pulumi.ResourceOptions(provider=provider, parent=self)

        # ------------------------------------------------------------------
        # SSH key pair - import local public key into this region.
        # The private key never leaves the local machine.
        # ------------------------------------------------------------------
        key_pair = aws.ec2.KeyPair(
            f"keypair-{node_name}",
            public_key=public_key_text,
            key_name=f"relay-{stack_name}",
            tags={"Name": f"relay-{stack_name}", "Stack": stack_name},
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # AMI lookup - latest Ubuntu 24.04 x86_64 in this region.
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
        # ------------------------------------------------------------------
        instance = aws.ec2.Instance(
            f"instance-{node_name}",
            ami=ami.id,
            instance_type=instance_type,
            subnet_id=net.subnet.id,
            vpc_security_group_ids=[net.sg_relay.id],
            key_name=key_pair.key_name,
            associate_public_ip_address=True,
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
                "Role":   "relay",
            },
            opts=child_opts,
        )

        # ------------------------------------------------------------------
        # Elastic IP - stable public address for game clients and
        # inter-relay ping/pong. Required because RELAY_PUBLIC_ADDRESS must
        # not change across instance stops/starts.
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

