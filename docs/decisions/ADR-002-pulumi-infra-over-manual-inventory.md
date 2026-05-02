# ADR-002: Use Pulumi Python to Provision AWS Infrastructure and Generate Ansible Inventory

**Date:** 2026-04-30<br>
**Status:** Accepted<br>
**Deciders:** developer<br>
**Related Tasks:** `infra/` Pulumi project - multi-region relay node provisioning<br>
**Related ADRs:** N/A<br>
**Related Sessions:** [Session 2026-04-30](../sessions/2026-04-30-pulumi-infra-plan.md)<br>

## Context

The project deploys relay-xdp nodes across 3 AWS regions (us-east-1, eu-west-1,
ap-southeast-1) and a relay-backend node. Previously, `ansible/inventory/production.yml`
and `ansible/inventory/staging.yml` contained hardcoded IP addresses that were managed
manually.

Problems with the manual approach:
- IPs must be known before running Ansible, coupling infrastructure creation to
  a manual step with no reproducibility guarantee.
- No audit trail for when/how instances were created or replaced.
- Replacing a node requires manually updating inventory, re-running Ansible, and
  hoping no state drifts.
- Multi-region setup (3 VPCs, 3 key pair imports, 6 security groups, 3 EIPs, 1
  backend instance) is too complex to manage by hand without codifying it.

The existing Ansible roles (`relay-xdp`, `relay-backend`, `common`, `redis`,
`kernel-module`) are complete, tested, and handle all software deployment correctly.
They do not need to be replaced - only the infrastructure provisioning step needs
to be automated.

## Options Considered

### Option A: Manual inventory (status quo)

- **Description:** Keep hardcoded IPs in `ansible/inventory/*.yml`. Operators create
  EC2 instances by hand via AWS Console or ad-hoc CLI commands, then update the YAML.
- **Pros:** No new tooling, zero learning curve | **Cons:** Not reproducible, no drift
  detection, error-prone multi-region setup, no state history, blocks CI/CD automation |
  **Effort:** Impl: None / Migration: None / Maintenance: High (every node change is manual)

### Option B: Pulumi Python (infrastructure as code) + `inventory_gen.py` bridge

- **Description:** Define all AWS resources (VPC, subnet, IGW, security groups, EC2,
  EIP, key pairs) in a Pulumi Python project under `infra/`. After `pulumi up`, run
  `infra/inventory_gen.py` to render Ansible inventory from stack outputs. Ansible
  pipeline is unchanged.
- **Pros:** Reproducible, state-tracked, drift-detectable, multi-region handled cleanly
  with per-region `pulumi_aws.Provider`, reuses existing Ansible roles unchanged,
  `pulumi preview` gives dry-run before any change | **Cons:** New dependency (Pulumi
  CLI + Python SDK), operators must learn `pulumi up` / `pulumi destroy` workflow |
  **Effort:** Impl: Medium / Migration: Low (inventory files replaced by generated output) /
  Maintenance: Low

### Option C: Replace Ansible with Pulumi for software deployment too

- **Description:** Use Pulumi's `Command` resource or a full Pulumi automation API to
  run software deployment steps, eliminating Ansible entirely.
- **Pros:** Single tool for infra + software | **Cons:** Complete rewrite of all Ansible
  roles (relay-xdp, relay-backend, common, redis, kernel-module), loss of idempotent
  `apt`, `systemd`, and vault-encrypted secrets handling that Ansible provides natively,
  significant regression risk | **Effort:** Impl: Very High / Migration: Very High /
  Maintenance: Medium

### Option D: Terraform instead of Pulumi

- **Description:** Use Terraform (HCL) for infrastructure provisioning, same
  `inventory_gen.py` bridge approach.
- **Pros:** Industry standard, wide documentation | **Cons:** HCL is less expressive than
  Python for per-region loops and component abstractions, no type safety, `terraform
  output -json` equivalent to `pulumi stack output --json` but HCL computed values
  are less ergonomic, project already uses Python for `infra/` | **Effort:** Impl: Medium /
  Migration: Low / Maintenance: Low

## Decision

**Chosen: Option B - Pulumi Python + `inventory_gen.py` bridge**

Pulumi Python provisions all AWS resources. `inventory_gen.py` reads stack outputs and
renders `ansible/inventory/<stack>.yml`. Ansible handles all software deployment
unchanged.

## Rationale

- Option A is unsustainable at 3 regions: 3 VPCs, 6 security groups, 3 EIPs, 3
  regional key pair imports are too many manual steps. One botched IP update silently
  deploys to the wrong host.
- Option C is high-risk rewrite with no benefit - Ansible roles are working and tested.
  The `inventory_gen.py` bridge preserves them at zero cost.
- Option D (Terraform) is equally valid technically, but Python is more expressive for
  the per-region `ComponentResource` pattern and the project has no existing Terraform
  state to migrate.
- Option B minimizes blast radius: Pulumi only touches infrastructure, Ansible only
  touches software. The boundary is the inventory file. Both sides can be tested
  independently (`pulumi preview` + `python3 infra/test_inventory_gen.py`).

Key deciding factors:
- `c5n.xlarge` must be pinned to specific AZs per region - a Python dict constant
  (`C5N_AZ_MAP`) is cleaner than HCL locals.
- Same SSH public key must be imported into 3 regions - a Python loop over
  `pulumi_aws.Provider` instances is idiomatic; HCL `for_each` on providers is awkward.
- S3 state backend avoids Pulumi Cloud vendor lock-in, consistent with self-hosted
  deployment model.

## Consequences

- **Positive:** Infrastructure is reproducible and auditable (`git log infra/`).
  `pulumi preview` catches mistakes before `pulumi up`. Replacing a relay node is
  `pulumi up` + `python infra/inventory_gen.py` + `ansible-playbook` - no manual IP
  tracking. Multi-region deployment is a config change (`relay_regions` list).
  Validated 2026-05-02: staging was expanded from 1 region (us-east-1) to 3 regions
  (us-east-1, eu-west-1, ap-southeast-1) by editing `Pulumi.staging.yaml` only - no
  code changes required. `pulumi up` created 53 resources across 3 regions in 2m47s.
- **Negative:** Operators need Pulumi CLI installed and S3 backend credentials
  configured. `pulumi up` is an additional step before Ansible. Each stack has 4 EIPs
  (3 relay + 1 backend): AWS charges $0.005/hr per idle EIP, so ~$0.02/hr per stack
  when all instances are stopped. Mitigate staging cost with `pulumi destroy --stack
  staging` when idle. Vault key names under `vault_relay_keys` in
  `playbooks/group_vars/<env>/vault.yml` must match Pulumi node names exactly
  (`relay-{stack_name}-{n}`, e.g. `relay-staging-1`, `relay-production-1`). Mismatch
  causes `ansible-playbook` to fail with `object of type 'dict' has no attribute
  '<relay-name>'`. Use `ansible/scripts/gen-vault-keys.sh` to generate correct names;
  when adding nodes to an existing stack, append new keypairs to the vault rather than
  regenerating all keys.
- **Neutral:** `ansible/inventory/production.yml` and `staging.yml` become generated
  files - do not edit manually, source of truth is Pulumi state. As of 2026-05-02,
  staging mirrors production topology (3 relay nodes across 3 regions + 1 backend),
  differing only in instance type: `t3.medium` (staging, XDP generic mode) vs
  `c5n.xlarge` (production, XDP native mode via ENA driver).

## Affected Components

| Component | Impact | Description |
|-----------|--------|-------------|
| `infra/` | High | New Pulumi Python project (11 files) |
| `ansible/inventory/*.yml` | Medium | Now generated by `inventory_gen.py`, not edited manually |
| `ansible/scripts/gen-vault-keys.sh` | Low | Generates vault keypairs with names matching Pulumi node names - staging: `relay-staging-{1,2,3}`, production: `relay-production-{1,2,3}` |
| `Makefile` | Low | New targets: `deploy-production`, `deploy-staging`, `infra-preview-*`, `infra-destroy-staging` |
| Ansible roles | None | Unchanged - Pulumi only provisions VMs |

## Revisit When

- A second operator joins: consider adding `pulumi whoami` / `pulumi org` access
  controls and documenting the S3 bucket IAM policy for shared access.
- Node count grows beyond 8 relays: evaluate whether `relay_regions` list config is
  still ergonomic or whether a more dynamic data-driven approach is needed.
- CI/CD pipeline is added: consider `pulumi up --non-interactive` in GitHub Actions
  with OIDC IAM role (Option B already supports this - no structural change needed).

## Migration Plan

1. Create S3 bucket for Pulumi state (`relay-xdp-pulumi-state`, versioning enabled).
2. `pulumi login s3://relay-xdp-pulumi-state?region=us-east-1`.
3. `pulumi stack init staging` + `pulumi stack init production`.
4. Set `admin_cidr` per stack: `pulumi config set admin_cidr "x.x.x.x/32"`.
5. `pulumi preview --stack staging` - verify 53 resources, 0 errors.
6. `pulumi up --stack staging` - provision staging infrastructure.
7. `python3 infra/inventory_gen.py --stack staging` - generate inventory.
8. `ansible-playbook -i ansible/inventory/staging.yml ansible/playbooks/site.yml` -
   deploy software (unchanged Ansible pipeline).
9. Repeat steps 6-8 for `production` stack when ready.
10. Archive the old hardcoded `ansible/inventory/*.yml` files (replaced by generated output).
