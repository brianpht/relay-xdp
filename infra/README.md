# relay-xdp-infra

Pulumi Python project - provisions AWS infrastructure for relay-xdp multi-region
node deployment. State is stored in an S3-compatible backend.

## Prerequisites

- Python 3.11+
- Pulumi CLI 3.x (https://www.pulumi.com/docs/install/)
- AWS credentials in `~/.aws/credentials` with a named profile
- An S3 bucket for Pulumi state storage

## Security: admin_cidr guard

`admin_cidr` controls which CIDR is whitelisted for SSH (port 22) on every node.

Two layers block an unsafe value from reaching AWS:

1. **Makefile preflight** - `make deploy-*` runs `make preflight` first. It greps
   both `Pulumi.production.yaml` and `Pulumi.staging.yaml` and aborts if either file
   still contains `0.0.0.0/0` or the `REPLACE_ME` placeholder string.

2. **Python validation** - `config._validate_admin_cidr` runs at the start of every
   `pulumi preview` / `pulumi up`. It rejects:
   - Any value containing `REQUIRED_OVERRIDE` or `REPLACE_ME`
   - IPv6 addresses (EC2 `cidr_blocks` only accepts IPv4; use `ipv6_cidr_blocks` separately)
   - `0.0.0.0/0` or `::/0` on the **production** stack (fatal error)
   - `0.0.0.0/0` on **staging** is a warning, not an error (explicit operator choice)

Both YAML files ship with `admin_cidr: REPLACE_ME/32`. You must set a real CIDR
before the first deploy (see First-Time Setup step 4).

## Environment Variables

Set these before running any `pulumi` or `aws` command:

```bash
# AWS profile to use (must have EC2 + S3 permissions - see IAM setup below)
export AWS_PROFILE=relay-xdp-infra

# Pulumi state backend - S3 bucket created once
export PULUMI_BACKEND_URL=s3://relay-xdp-pulumi-state?region=us-east-1

# Passphrase to encrypt stack secrets (keep consistent per stack)
# staging stack:
export PULUMI_CONFIG_PASSPHRASE="staging"
# production stack:
export PULUMI_CONFIG_PASSPHRASE="<production-passphrase>"
```

Add these to `~/.bashrc` or a project `.envrc` (e.g. with `direnv`) so they persist
across sessions. Never commit `PULUMI_CONFIG_PASSPHRASE` to source control.

## First-Time Setup

```bash
# 1 - Install Python dependencies (run once per machine)
cd infra/
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2 - Log in to S3 state backend
export AWS_PROFILE=relay-xdp-infra
pulumi login s3://relay-xdp-pulumi-state?region=us-east-1

# 3 - Create stacks (run once)
export PULUMI_CONFIG_PASSPHRASE="staging"
pulumi stack init staging --non-interactive

export PULUMI_CONFIG_PASSPHRASE="<production-passphrase>"
pulumi stack init production --non-interactive

# 4 - Set admin SSH CIDR to your operator public IPv4.
#     Use -4 to force IPv4 (EC2 security groups require IPv4 CIDR notation).
export PULUMI_CONFIG_PASSPHRASE="staging"
pulumi config set relay-xdp-infra:admin_cidr "$(curl -4 -s ifconfig.me)/32" --stack staging

export PULUMI_CONFIG_PASSPHRASE="<production-passphrase>"
pulumi config set relay-xdp-infra:admin_cidr "$(curl -4 -s ifconfig.me)/32" --stack production
```

## Deploy

```bash
# --- Staging ---
export AWS_PROFILE=relay-xdp-infra
export PULUMI_BACKEND_URL=s3://relay-xdp-pulumi-state?region=us-east-1
export PULUMI_CONFIG_PASSPHRASE="staging"

# Dry run (no Makefile preflight - use for manual inspection)
pulumi preview --stack staging --cwd infra/

# Apply
pulumi up --stack staging --cwd infra/

# Generate Ansible inventory from outputs
python infra/inventory_gen.py --stack staging

# --- Production ---
export PULUMI_CONFIG_PASSPHRASE="<production-passphrase>"

pulumi preview --stack production --cwd infra/
pulumi up --stack production --cwd infra/
python infra/inventory_gen.py --stack production
```

The top-level `Makefile` wraps these three steps and runs `make preflight` first:

```bash
# Runs preflight -> pulumi up -> inventory_gen -> ansible-playbook
make deploy-staging    RELAY_VERSION=v1.0.0
make deploy-production RELAY_VERSION=v1.0.0

# Dry-run previews (no AWS changes, no Makefile preflight)
make infra-preview-staging
make infra-preview-production
```

`make preflight` can also be run standalone at any time:

```bash
make preflight   # exits non-zero if admin_cidr is 0.0.0.0/0 or REPLACE_ME in either YAML
```

## IAM Setup

The `relay-xdp-infra` AWS profile needs the following permissions:

- `ec2:*` on `*` (multi-region: cannot scope by ARN)
- `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket` on `relay-xdp-pulumi-state`

See the IAM policy in `docs/sessions/2026-04-30-pulumi-infra-plan.md` for the full JSON.

Create the profile after generating an access key for `relay-xdp-infra` IAM user:

```bash
aws configure --profile relay-xdp-infra
# AWS Access Key ID:     AKIA...
# AWS Secret Access Key: ...
# Default region name:   us-east-1
# Default output format: json
```

## Stack Config Reference

| Key | Production | Staging | Description |
|-----|-----------|---------|-------------|
| `relay_regions` | `[us-east-1, eu-west-1, ap-southeast-1]` | `[us-east-1, eu-west-1, ap-southeast-1]` | AWS regions for relay nodes |
| `relay_count` | `3` | `3` | Number of relay nodes |
| `relay_instance_type` | `c5n.xlarge` | `t3.medium` | EC2 type for relay nodes |
| `backend_region` | `us-east-1` | `us-east-1` | Region for backend node |
| `backend_instance_type` | `c5.large` | `t3.medium` | EC2 type for backend |
| `key_pub_path` | `~/.ssh/personal-key.pub` | same | Local SSH public key path |
| `admin_cidr` | your IPv4/32 (**required**) | your IPv4/32 (**required**) | SSH whitelist CIDR; ships as `REPLACE_ME/32`; must be set before first deploy (see step 4) |

## Instance Type Rationale

- `c5n.xlarge` - ena (Elastic Network Adapter) driver supports XDP native mode
  (driver-level packet processing). Required for the sub-microsecond packet
  forwarding budget. Not available in all AZs - see `config.py:C5N_AZ_MAP`.
- `t3.medium` - XDP generic mode only (acceptable for staging/testing).
  Also usable with `RELAY_NO_BPF=1` for pure userspace testing.

## WARNING: EIP Cost

Each node (relay + backend) has an Elastic IP. AWS charges $0.005/hr per EIP
when the associated instance is stopped (but not terminated).

Current EIP count per stack:
- Staging:    4 EIPs (3 relay + 1 backend) = ~$0.02/hr when all instances stopped
- Production: 4 EIPs (3 relay + 1 backend) = ~$0.02/hr when all instances stopped

Run `pulumi destroy --stack staging` when staging is not in use to avoid idle charges.
Production EIPs are intentionally persistent - destroying them invalidates game client
configs that reference relay public addresses.

## File Structure

```
infra/
├── Pulumi.yaml                      # project metadata
├── Pulumi.production.yaml           # production stack config (admin_cidr: REPLACE_ME/32)
├── Pulumi.staging.yaml              # staging stack config   (admin_cidr: REPLACE_ME/32)
├── requirements.txt                 # pulumi>=3, pulumi-aws>=6, PyYAML>=6
├── __main__.py                      # entrypoint - orchestrates all resources
├── config.py                        # InfraConfig, _validate_admin_cidr, constants
├── network.py                       # create_regional_network() -> VPC + SGs
├── relay_node.py                    # RelayNode ComponentResource
├── backend_node.py                  # BackendNode ComponentResource
├── inventory_gen.py                 # CLI: pulumi output -> ansible/inventory/<stack>.yml
├── test_admin_cidr_validation.py    # unit tests for _validate_admin_cidr
└── test_inventory_gen.py            # unit tests for inventory_gen
```
