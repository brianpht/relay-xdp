#!/usr/bin/env bash
# ansible/scripts/encrypt-vault.sh
#
# Encrypt vault files for staging and/or production.
#
# Usage:
#   # Interactive (prompts for vault password):
#   ./scripts/encrypt-vault.sh staging
#   ./scripts/encrypt-vault.sh production
#   ./scripts/encrypt-vault.sh all
#
#   # Non-interactive (vault password from file):
#   VAULT_PASSWORD_FILE=~/.vault_pass ./scripts/encrypt-vault.sh staging
#
# Workflow for first-time setup:
#   1. Generate keys:
#        ./scripts/gen-vault-keys.sh staging    > /tmp/vault_staging_plain.yml
#        ./scripts/gen-vault-keys.sh production > /tmp/vault_production_plain.yml
#   2. Copy into group_vars:
#        cp /tmp/vault_staging_plain.yml    group_vars/vault_staging.yml
#        cp /tmp/vault_production_plain.yml group_vars/vault_production.yml
#   3. Encrypt:
#        ./scripts/encrypt-vault.sh all
#   4. Shred plaintext:
#        shred -u /tmp/vault_staging_plain.yml /tmp/vault_production_plain.yml
#   5. Commit encrypted vault files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="$(dirname "$SCRIPT_DIR")"

ENVIRONMENT="${1:-all}"

encrypt_file() {
  local env="$1"
  local vault_file="$ANSIBLE_DIR/group_vars/vault_${env}.yml"

  if [[ ! -f "$vault_file" ]]; then
    echo "Error: $vault_file not found. Run gen-vault-keys.sh first." >&2
    return 1
  fi

  # Check if already encrypted
  if head -1 "$vault_file" | grep -q '^\$ANSIBLE_VAULT'; then
    echo "$vault_file is already encrypted. Use 'ansible-vault rekey' to change password." >&2
    return 0
  fi

  local vault_args=()
  if [[ -n "${VAULT_PASSWORD_FILE:-}" ]]; then
    vault_args+=(--vault-password-file "$VAULT_PASSWORD_FILE")
  fi

  echo "Encrypting $vault_file..."
  ansible-vault encrypt "${vault_args[@]}" "$vault_file"
  echo "Done: $vault_file encrypted."
}

case "$ENVIRONMENT" in
  staging)
    encrypt_file staging
    ;;
  production)
    encrypt_file production
    ;;
  all)
    encrypt_file staging
    encrypt_file production
    ;;
  *)
    echo "Usage: $0 <staging|production|all>" >&2
    exit 1
    ;;
esac

