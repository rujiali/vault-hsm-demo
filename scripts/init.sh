#!/bin/bash
# Initialise vault-main (auto-unseals via vault-hsm Transit seal)
set -e

export VAULT_ADDR=http://localhost:8200

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Waiting for vault-main to be ready..."
until curl -s $VAULT_ADDR/v1/sys/health 2>/dev/null | python3 -c "import sys,json; json.load(sys.stdin)" > /dev/null 2>&1; do
  sleep 2
done

echo "==> Initialising vault-main..."
INIT_OUTPUT=$(vault operator init -recovery-shares=1 -recovery-threshold=1 -format=json)
ROOT_TOKEN=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
echo "$INIT_OUTPUT" > "$SCRIPT_DIR/vault-main-init.json"
echo "    Init complete. Keys saved to vault-main-init.json (gitignored)"

echo "==> Vault is using Transit Auto-Unseal via vault-hsm — no manual unseal needed"
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

echo ""
echo "==> Setup complete!"
echo "    vault-main UI : http://localhost:8200"
echo "    Root token    : $ROOT_TOKEN"
echo ""
echo "    Run the demo  : ./scripts/demo.sh"
