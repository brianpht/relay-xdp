# relay-xdp-infra

Pulumi Python project - provisions AWS infrastructure for relay-xdp multi-region
node deployment. State is stored in an S3-compatible backend.

## Prerequisites

- Python 3.11+
- Pulumi CLI 3.x (`pip install pulumi` or https://www.pulumi.com/docs/install/)
- AWS credentials configured (`aws configure` or environment variables)
- An S3 bucket for Pulumi state storage

## First-Time Setup

```bash
# 1 - Log in to S3 state backend
pulumi login s3://<your-bucket>?region=us-east-1

# 2 - Create stacks
cd infra/
pulumi stack init production
pulumi stack init staging

# 3 - Set admin SSH CIDR (replace with your actual IP)
pulumi config set admin_cidr "203.0.113.5/32" --stack production
pulumi config set admin_cidr "203.0.113.5/32" --stack staging

# 4 - Install Python dependencies
pip install -r requirements.txt
```

## Deploy

```bash
# Preview changes (dry run)
pulumi preview --stack production

# Apply
pulumi up --stack production

# Generate Ansible inventory from outputs
python infra/inventory_gen.py --stack production

# Run Ansible (software deployment)
ansible-playbook -i ansible/inventory/production.yml \
    ansible/playbooks/site.yml \
    -e relay_version=v1.0.0 \
    --ask-vault-pass
```

The top-level `Makefile` provides `make deploy-production` and `make deploy-staging`
targets that run all three steps in order.

## Stack Config Reference

| Key | Production | Staging | Description |
|-----|-----------|---------|-------------|
| `relay_regions` | `[us-east-1, eu-west-1, ap-southeast-1]` | `[us-east-1]` | AWS regions for relay nodes |
| `relay_count` | `3` | `1` | Number of relay nodes |
| `relay_instance_type` | `c5n.xlarge` | `t3.medium` | EC2 type for relay nodes |
| `backend_region` | `us-east-1` | `us-east-1` | Region for backend node |
| `backend_instance_type` | `c5.large` | `t3.medium` | EC2 type for backend |
| `key_pub_path` | `~/.ssh/id_ed25519.pub` | same | Local SSH public key path |
| `admin_cidr` | your IP/32 | your IP/32 | SSH whitelist CIDR |

## Instance Type Rationale

- `c5n.xlarge` - ena (Elastic Network Adapter) driver supports XDP native mode
  (driver-level packet processing). Required for the sub-microsecond packet
  forwarding budget. Not available in all AZs - see `config.py:C5N_AZ_MAP`.
- `t3.medium` - XDP generic mode only (acceptable for staging/testing).
  Also usable with `RELAY_NO_BPF=1` for pure userspace testing.

## WARNING: EIP Cost

Each relay node in production has an Elastic IP. AWS charges $0.005/hr per EIP
when the associated instance is stopped (but not terminated). Run
`pulumi destroy --stack staging` when staging is not in use to avoid idle EIP
charges.

## File Structure

```
infra/
├── Pulumi.yaml              # project metadata
├── Pulumi.production.yaml   # production stack config
├── Pulumi.staging.yaml      # staging stack config
├── requirements.txt         # pulumi>=3, pulumi-aws>=6, PyYAML>=6
├── __main__.py              # entrypoint - orchestrates all resources
├── config.py                # InfraConfig, constants (CIDRs, AZ map, AMI filter)
├── network.py               # create_regional_network() -> VPC + SGs
├── relay_node.py            # RelayNode ComponentResource
├── backend_node.py          # BackendNode ComponentResource
└── inventory_gen.py         # CLI: pulumi output -> ansible/inventory/<stack>.yml
```

