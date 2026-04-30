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
    staging.yml             - Staging hosts (includes 'staging' group for group_vars auto-load)
    production.yml          - Production hosts (includes 'production' group for group_vars auto-load)
  playbooks/
    site.yml                - Full deploy (ordered)
    relay-only.yml          - Redeploy relays only (rolling)
    module-only.yml         - Update kernel module only
    rollback.yml            - Manual rollback to previous version
    group_vars/             - Adjacent to playbooks for auto-discovery
      all.yml               - Shared defaults
      staging/
        vars.yml            - Staging overrides
        vault.yml           - Ansible Vault encrypted secrets (staging)
      production/
        vars.yml            - Production overrides
        vault.yml           - Ansible Vault encrypted secrets (production)
  roles/
    common/                 - Base OS: kernel check, user, packages, sysctl
    kernel-module/          - Download + load relay_module-<kver>.ko
    relay-backend/          - Binary + systemd + env
    relay-xdp/              - Binary + eBPF obj + systemd + env (with backup)
    redis/                  - Install + configure Redis 7
  scripts/
    gen-vault-keys.sh       - Generate X25519 keypairs, output plaintext YAML for vault
    encrypt-vault.sh        - Encrypt vault files with ansible-vault
```

## Quick Start

### 1. Set up vault secrets

```bash
cd ansible

# Generate keypairs and encrypt immediately
./scripts/gen-vault-keys.sh staging > /tmp/vault_staging_plain.yml
ansible-vault encrypt --output playbooks/group_vars/staging/vault.yml /tmp/vault_staging_plain.yml
shred -u /tmp/vault_staging_plain.yml

# Production (same flow)
./scripts/gen-vault-keys.sh production > /tmp/vault_production_plain.yml
ansible-vault encrypt --output playbooks/group_vars/production/vault.yml /tmp/vault_production_plain.yml
shred -u /tmp/vault_production_plain.yml
```

### 2. Full deploy to staging

```bash
cd ansible
ansible-playbook -i inventory/staging.yml playbooks/site.yml \
  -e relay_version=v1.2.3 \
  --ask-vault-pass
```

### 3. Rolling deploy to production

```bash
cd ansible
ansible-playbook -i inventory/production.yml playbooks/site.yml \
  -e relay_version=v1.2.3 \
  --ask-vault-pass
```

Deploys relay nodes one at a time (`serial: 1`). Verifies each node before
proceeding. Stops on first failure - run `rollback.yml` to restore.

### 4. Rollback a failed node

```bash
cd ansible
ansible-playbook -i inventory/production.yml playbooks/rollback.yml \
  --limit relay-prod-2 \
  --ask-vault-pass
```

## group_vars Auto-Discovery

`playbooks/group_vars/` is adjacent to `playbooks/site.yml`, so Ansible
auto-discovers all vars and vault files without any `-e @group_vars/...` flags.

- `playbooks/group_vars/all.yml` - loaded for every host
- `playbooks/group_vars/staging/vars.yml` + `vault.yml` - loaded for the `staging` group
- `playbooks/group_vars/production/vars.yml` + `vault.yml` - loaded for the `production` group

The inventories define a `staging` / `production` parent group that contains
`relay_servers` and `backend_servers`, triggering the correct group_vars load.

## Environment Differences

| Setting            | Staging  | Production |
|--------------------|----------|------------|
| `rust_log`         | info     | warn       |
| `relay_dedicated`  | false    | true       |
| `redis_maxmemory`  | 256mb    | 1gb        |
| `relay_serial`     | all      | 1 (rolling)|

## Secrets

Secrets are stored in Ansible Vault encrypted files:
- `playbooks/group_vars/staging/vault.yml`
- `playbooks/group_vars/production/vault.yml`

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

