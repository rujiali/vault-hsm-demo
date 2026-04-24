#!/bin/bash
# Initialise vault-main (auto-unseals via PKCS#11 — libvault-pkcs11.so speaks KMIP to vault-hsm)
set -e

export VAULT_ADDR=http://localhost:8200

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Waiting for vault-main to be ready..."
until curl -s $VAULT_ADDR/v1/sys/health 2>/dev/null | python3 -c "import sys,json; json.load(sys.stdin)" > /dev/null 2>&1; do
  sleep 2
done

INITIALIZED=$(curl -s $VAULT_ADDR/v1/sys/health | python3 -c "import sys,json; s=json.load(sys.stdin); print('true' if s.get('initialized') else 'false')")

if [ "$INITIALIZED" = "false" ]; then
  echo "==> Initialising vault-main..."
  INIT_OUTPUT=$(vault operator init -recovery-shares=1 -recovery-threshold=1 -format=json)
  echo "$INIT_OUTPUT" > "$SCRIPT_DIR/vault-main-init.json"
  echo "    Init complete. Keys saved to vault-main-init.json (gitignored)"
else
  echo "==> vault-main already initialised — loading saved keys from vault-main-init.json"
  INIT_OUTPUT=$(cat "$SCRIPT_DIR/vault-main-init.json")
fi

ROOT_TOKEN=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")

echo "==> Vault is using PKCS#11 Auto-Unseal via vault-hsm KMIP — no manual unseal needed"
sleep 2

# Confirm unsealed
STATUS=$(curl -sf $VAULT_ADDR/v1/sys/health | python3 -c "import sys,json; s=json.load(sys.stdin); print('sealed' if s.get('sealed') else 'unsealed')")
echo "    Status: $STATUS"

export VAULT_TOKEN=$ROOT_TOKEN

echo "==> Enabling Transit secrets engine (Encryption as a Service)..."
vault secrets enable transit

echo "==> Creating encryption key..."
vault write -f transit/keys/demo-key

echo "==> Setting up separation of duties policies..."

vault policy write encrypt-only - <<'EOF'
path "transit/encrypt/demo-key" {
  capabilities = ["create", "update"]
}
EOF

vault policy write decrypt-only - <<'EOF'
path "transit/decrypt/demo-key" {
  capabilities = ["create", "update"]
}
EOF

vault policy write key-admin - <<'EOF'
path "transit/keys/demo-key" {
  capabilities = ["read"]
}
path "transit/keys/demo-key/rotate" {
  capabilities = ["create", "update"]
}
EOF

echo "==> Setting up key governance controls..."

# Explicitly lock down demo-key
vault write transit/keys/demo-key/config \
  deletion_allowed=false

# Create a second key for governance demo — exportable, deletable
vault write -f transit/keys/demo-key-managed
vault write transit/keys/demo-key-managed/config \
  exportable=true \
  deletion_allowed=true

# Key viewer — read key metadata only, no operations
vault policy write key-viewer - <<'EOF'
path "transit/keys/demo-key" {
  capabilities = ["read"]
}
path "transit/keys/demo-key-managed" {
  capabilities = ["read"]
}
EOF

# Key custodian — can approve control group requests
vault policy write key-custodian - <<'EOF'
path "sys/control-group/authorize" {
  capabilities = ["create", "update"]
}
path "sys/control-group/request" {
  capabilities = ["read", "update"]
}
path "transit/export/encryption-key/demo-key-managed" {
  capabilities = ["read"]
}
EOF

# Key destroyer — can enable deletion and delete key
vault policy write key-destroyer - <<'EOF'
path "transit/keys/demo-key-managed/config" {
  capabilities = ["create", "update"]
}
path "transit/keys/demo-key-managed" {
  capabilities = ["delete"]
}
EOF

# Key exporter — export requires control group approval
vault policy write key-exporter - <<'EOF'
path "transit/export/encryption-key/demo-key-managed" {
  capabilities = ["read"]
  control_group = {
    ttl = "1h"
    factor "authorise" {
      identity {
        group_names = ["key-custodians"]
        approvals   = 1
      }
    }
  }
}
EOF

echo "==> Enabling userpass auth for control group demo..."
vault auth enable userpass

# Create custodian user
vault write auth/userpass/users/custodian \
  password=custodian123 \
  policies=key-custodian

# Create entity for custodian and link to userpass
ACCESSOR=$(vault auth list -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['userpass/']['accessor'])")

ENTITY_ID=$(vault write -format=json identity/entity \
  name="custodian" \
  policies="key-custodian" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")

vault write identity/entity-alias \
  name="custodian" \
  canonical_id="$ENTITY_ID" \
  mount_accessor="$ACCESSOR"

# Create key-custodians group and add custodian entity
vault write identity/group \
  name="key-custodians" \
  type="internal" \
  policies="key-custodian" \
  member_entity_ids="$ENTITY_ID"

echo "==> Applying Sentinel policy — restrict export to business hours..."
SENTINEL_B64=$(python3 -c "
import base64
policy = '''
import \"time\"
import \"sockaddr\"

# Allow export only during business hours (9am-5pm)
main = rule {
    time.now.hour >= 9 and time.now.hour < 17
}
'''
print(base64.b64encode(policy.encode()).decode())
")

vault write sys/policies/egp/export-business-hours \
  policy="$SENTINEL_B64" \
  paths='["transit/export/*"]' \
  enforcement_level="soft-mandatory"

echo ""
echo "==> Setup complete!"
echo "    vault-main UI      : http://localhost:8200"
echo "    Root token         : $ROOT_TOKEN"
echo "    Custodian user     : custodian / custodian123"
echo ""
echo "    Run the demo       : ./scripts/demo.sh"
