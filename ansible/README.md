# ansible/

Ansible-based bare-metal deployment for the relay-xdp stack.
No Docker in staging/production - binaries deployed directly, managed by systemd.

## Prerequisites

```
pip install ansible ansible-core
ansible-galaxy collection install community.general ansible.posix
```

## Directory Structure

```
ansible/
  ansible.cfg               - Ansible defaults (inventory path, SSH config)
  inventory/
    staging.yml             - Staging hosts
    production.yml          - Production hosts
  group_vars/
    all.yml                 - Shared defaults
    staging.yml             - Staging overrides
    production.yml          - Production overrides
    vault_staging.yml       - Ansible Vault encrypted secrets (staging)
    vault_production.yml    - Ansible Vault encrypted secrets (production)
  roles/
    common/                 - Base OS: kernel check, user, packages, sysctl
    kernel-module/          - Download + load relay_module-<kver>.ko
    relay-backend/          - Binary + systemd + env
    relay-xdp/              - Binary + eBPF obj + systemd + env (with backup)
    redis/                  - Install + configure Redis 7
  playbooks/
    site.yml                - Full deploy (ordered)
    relay-only.yml          - Redeploy relays only (rolling)
    module-only.yml         - Update kernel module only
    rollback.yml            - Manual rollback to previous version
```

## Quick Start

### 1. Set up vault secrets

```bash
# Staging
ansible-vault create group_vars/vault_staging.yml
# Add:
# vault_relay_backend_public_key: "..."
# vault_relay_backend_private_key: "..."
# vault_relay_keys:
#   relay-staging-1:
#     public_key: "..."
#     private_key: "..."

# Production (same structure)
ansible-vault create group_vars/vault_production.yml
```

### 2. Full deploy to staging

```bash
ansible-playbook -i inventory/staging.yml playbooks/site.yml \
  -e relay_version=v1.2.3 \
  --ask-vault-pass
```

### 3. Rolling deploy to production

```bash
ansible-playbook -i inventory/production.yml playbooks/site.yml \
  -e relay_version=v1.2.3 \
  --ask-vault-pass
```

Deploys relay nodes one at a time (`serial: 1`). Verifies each node before
proceeding. Stops on first failure - run `rollback.yml` to restore.

### 4. Rollback a failed node

```bash
ansible-playbook -i inventory/production.yml playbooks/rollback.yml \
  --limit relay-prod-2 \
  --ask-vault-pass
```

## Environment Differences

| Setting            | Staging  | Production |
|--------------------|----------|------------|
| `rust_log`         | info     | warn       |
| `relay_dedicated`  | false    | true       |
| `redis_maxmemory`  | 256mb    | 1gb        |
| `relay_serial`     | all      | 1 (rolling)|

## Secrets

Secrets are stored in Ansible Vault encrypted files:
- `group_vars/vault_staging.yml`
- `group_vars/vault_production.yml`

The vault password is stored in GitHub Secrets as `ANSIBLE_VAULT_PASSWORD`
and passed to Ansible via `--vault-password-file` in CI.

## Kernel Module Matrix

The kernel module must match the exact running kernel version.
Pre-built `.ko` files are published to GitHub Releases by the CI pipeline.

If you add a new kernel version to staging/production, update the matrix in
`.github/workflows/build-release.yml` and release a new version.

## Verification Steps (per relay node)

1. `systemctl is-active relay-xdp` - service running
2. `bpftool prog list | grep xdp` - BPF program loaded
3. `lsmod | grep relay_module` - kernel module present
4. Journal check for startup log entry

