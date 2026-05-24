#!/usr/bin/env bash
# ansible/scripts/gen-vault-keys.sh
#
# Generate X25519 keypairs for relay-xdp deployment.
#
# MODE 1 - First-time setup (generates all keys to stdout):
#   ./scripts/gen-vault-keys.sh staging   > /tmp/vault_staging_plain.yml
#   ./scripts/gen-vault-keys.sh production > /tmp/vault_production_plain.yml
#
#   Then encrypt immediately:
#     ansible-vault encrypt --output playbooks/group_vars/staging/vault.yml    /tmp/vault_staging_plain.yml
#     ansible-vault encrypt --output playbooks/group_vars/production/vault.yml /tmp/vault_production_plain.yml
#     shred -u /tmp/vault_staging_plain.yml /tmp/vault_production_plain.yml
#
# MODE 2 - Add new relay keys to an existing vault (safe: does not touch existing keys):
#   ./scripts/gen-vault-keys.sh staging --add relay-staging-4 relay-staging-5
#   ./scripts/gen-vault-keys.sh production --add relay-production-4 relay-production-5
#
#   Non-interactive (vault password from file):
#     VAULT_PASSWORD_FILE=~/.vault_pass_staging \
#       ./scripts/gen-vault-keys.sh staging --add relay-staging-4 relay-staging-5
#
#   The --add mode:
#     1. Decrypts the existing vault to a temp file
#     2. Appends keypairs for each named relay (skips if already present)
#     3. Re-encrypts vault in place
#     4. Shreds the temp plaintext file
#
# Requirements:
#   - python3 with 'cryptography' package  (pip install cryptography)
#     OR openssl 1.1+ (fallback)
#   - ansible-vault in PATH (--add mode only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="$(dirname "$SCRIPT_DIR")"

ENVIRONMENT="${1:-}"
if [[ -z "$ENVIRONMENT" ]]; then
  echo "Usage: $0 <staging|production> [--add relay-name ...]" >&2
  exit 1
fi

if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
  echo "Error: environment must be 'staging' or 'production'" >&2
  exit 1
fi

shift  # consume ENVIRONMENT; remaining args are optional --add + relay names

# ---------------------------------------------------------------------------
# Key generation helper - outputs base64-encoded 32-byte X25519 private/public
# ---------------------------------------------------------------------------
gen_keypair_python() {
  python3 - <<'PYEOF'
import sys
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    key = X25519PrivateKey.generate()
    priv = key.private_bytes_raw()
    pub  = key.public_key().public_bytes_raw()
    print(base64.b64encode(priv).decode())
    print(base64.b64encode(pub).decode())
except ImportError:
    sys.exit(1)
PYEOF
}

gen_keypair_openssl() {
  # Requires openssl 1.1+ for x25519 support.
  local pem priv pub
  pem=$(openssl genpkey -algorithm x25519 2>/dev/null)
  priv=$(echo "$pem" | openssl pkey -outform DER 2>/dev/null | tail -c 32 | base64)
  pub=$(echo "$pem"  | openssl pkey -pubout -outform DER 2>/dev/null | tail -c 32 | base64)
  echo "$priv"
  echo "$pub"
}

gen_keypair() {
  local result
  result=$(gen_keypair_python 2>/dev/null) && echo "$result" && return 0
  result=$(gen_keypair_openssl 2>/dev/null) && echo "$result" && return 0
  echo "Error: could not generate keypair. Install python3-cryptography or openssl 1.1+." >&2
  exit 1
}

read_key() {
  # $1 = variable name to store private key
  # $2 = variable name to store public key
  local pair
  pair=$(gen_keypair)
  local priv pub
  priv=$(echo "$pair" | sed -n '1p')
  pub=$(echo "$pair"  | sed -n '2p')
  printf -v "$1" '%s' "$priv"
  printf -v "$2" '%s' "$pub"
}

# ---------------------------------------------------------------------------
# MODE 2: --add <relay-name> [relay-name ...]
# Decrypts existing vault, appends new relay keypairs, re-encrypts in place.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--add" ]]; then
  shift  # consume --add
  NEW_RELAYS=("$@")
  if [[ ${#NEW_RELAYS[@]} -eq 0 ]]; then
    echo "Error: --add requires at least one relay name." >&2
    echo "Usage: $0 <staging|production> --add relay-name [relay-name ...]" >&2
    exit 1
  fi

  VAULT_FILE="$ANSIBLE_DIR/playbooks/group_vars/${ENVIRONMENT}/vault.yml"
  if [[ ! -f "$VAULT_FILE" ]]; then
    echo "Error: $VAULT_FILE not found. Run first-time setup first." >&2
    exit 1
  fi

  VAULT_ARGS=()
  if [[ -n "${VAULT_PASSWORD_FILE:-}" && ! "${VAULT_PASSWORD_FILE}" == /dev/fd/* ]]; then
    VAULT_ARGS+=(--vault-password-file "$VAULT_PASSWORD_FILE")
  else
    VAULT_ARGS+=(--ask-vault-pass)
  fi

  TMP_PLAIN=$(mktemp /tmp/vault_plain_XXXXXX.yml)
  trap 'shred -ufv "$TMP_PLAIN" 2>/dev/null || rm -f "$TMP_PLAIN"; echo "Temp plaintext shredded." >&2' EXIT

  echo "Decrypting $VAULT_FILE..." >&2
  ansible-vault decrypt "${VAULT_ARGS[@]}" --output "$TMP_PLAIN" "$VAULT_FILE"

  if ! grep -q '^vault_relay_keys:' "$TMP_PLAIN"; then
    echo "Error: vault_relay_keys block not found in decrypted vault." >&2
    exit 1
  fi

  for relay in "${NEW_RELAYS[@]}"; do
    if grep -q "^  ${relay}:" "$TMP_PLAIN"; then
      echo "WARNING: $relay already present in vault - skipping." >&2
      continue
    fi
    echo "Generating keypair for $relay..." >&2
    read_key relay_priv relay_pub
    cat >> "$TMP_PLAIN" <<EOF
  ${relay}:
    public_key:  "${relay_pub}"
    private_key: "${relay_priv}"
EOF
    echo "  Added $relay (pub: ${relay_pub:0:12}...)" >&2
  done

  echo "Re-encrypting $VAULT_FILE..." >&2
  ansible-vault encrypt "${VAULT_ARGS[@]}" --output "$VAULT_FILE" "$TMP_PLAIN"
  echo "Done: $VAULT_FILE updated. Re-run Ansible to deploy new relay keys." >&2
  exit 0
fi

# ---------------------------------------------------------------------------
# MODE 1: Generate all keys to stdout (first-time setup)
# ---------------------------------------------------------------------------
echo "# Ansible Vault - plaintext template for: $ENVIRONMENT" >&2
echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2
echo "# ENCRYPT IMMEDIATELY - do not commit this file unencrypted." >&2
echo "" >&2

if [[ "$ENVIRONMENT" == "staging" ]]; then
  RELAY_NAMES=("relay-staging-1" "relay-staging-2" "relay-staging-3" "relay-staging-4" "relay-staging-5")
else
  # Node names must match Pulumi output: relay-{stack_name}-{n}
  # stack_name for production stack = "production"
  RELAY_NAMES=("relay-production-1" "relay-production-2" "relay-production-3" "relay-production-4" "relay-production-5")
fi

# Backend keypair
echo "Generating backend keypair..." >&2
read_key backend_priv backend_pub

cat <<EOF
---
# group_vars/${ENVIRONMENT}/vault.yml - ENCRYPT WITH ansible-vault BEFORE COMMITTING
# ansible-vault encrypt group_vars/${ENVIRONMENT}/vault.yml

# relay-backend X25519 keypair
# The backend private key is used by relay-backend to decrypt relay handshakes.
# Relay nodes only need the backend public key.
vault_relay_backend_public_key:  "${backend_pub}"
vault_relay_backend_private_key: "${backend_priv}"

# Per-relay X25519 keypairs
# Each relay node has its own keypair.
# RELAY_PUBLIC_KEY and RELAY_PRIVATE_KEY env vars are set from these.
vault_relay_keys:
EOF

for relay in "${RELAY_NAMES[@]}"; do
  echo "Generating keypair for $relay..." >&2
  read_key relay_priv relay_pub
  cat <<EOF
  ${relay}:
    public_key:  "${relay_pub}"
    private_key: "${relay_priv}"
EOF
done
