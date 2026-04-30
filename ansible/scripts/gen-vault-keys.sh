#!/usr/bin/env bash
# ansible/scripts/gen-vault-keys.sh
#
# Generate X25519 keypairs for relay-xdp deployment and output
# plaintext YAML suitable for ansible-vault.
#
# Usage:
#   ./scripts/gen-vault-keys.sh staging   > /tmp/vault_staging_plain.yml
#   ./scripts/gen-vault-keys.sh production > /tmp/vault_production_plain.yml
#
# Then encrypt immediately:
#   ansible-vault encrypt --output playbooks/group_vars/staging/vault.yml    /tmp/vault_staging_plain.yml
#   ansible-vault encrypt --output playbooks/group_vars/production/vault.yml /tmp/vault_production_plain.yml
#   shred -u /tmp/vault_staging_plain.yml /tmp/vault_production_plain.yml
#
# Requirements:
#   - python3 with 'cryptography' package  (pip install cryptography)
#     OR openssl 1.1+ (fallback, see below)

set -euo pipefail

ENVIRONMENT="${1:-}"
if [[ -z "$ENVIRONMENT" ]]; then
  echo "Usage: $0 <staging|production>" >&2
  exit 1
fi

if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
  echo "Error: environment must be 'staging' or 'production'" >&2
  exit 1
fi

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
  # Private key is the last 32 bytes of DER output.
  # Public key is derived via openssl pkey -pubout.
  local tmp
  tmp=$(mktemp)
  openssl genpkey -algorithm x25519 -outform DER > "$tmp" 2>/dev/null
  local priv pub pem
  priv=$(tail -c 32 "$tmp" | base64)
  pem=$(openssl genpkey -algorithm x25519 2>/dev/null)
  pub=$(echo "$pem" | openssl pkey -pubout -outform DER 2>/dev/null | tail -c 32 | base64)
  rm -f "$tmp"
  # Re-generate cleanly using PEM to get consistent keypair
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
# Generate keys per environment
# ---------------------------------------------------------------------------
echo "# Ansible Vault - plaintext template for: $ENVIRONMENT" >&2
echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2
echo "# ENCRYPT IMMEDIATELY - do not commit this file unencrypted." >&2
echo "" >&2

if [[ "$ENVIRONMENT" == "staging" ]]; then
  RELAY_NAMES=("relay-staging-1")
else
  RELAY_NAMES=("relay-prod-1" "relay-prod-2" "relay-prod-3")
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

