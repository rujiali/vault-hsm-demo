#!/bin/bash
set -e

export VAULT_ADDR=http://localhost:8200

echo "==> Waiting for Vault to be ready..."
until curl -sf $VAULT_ADDR/v1/sys/health > /dev/null 2>&1; do
  sleep 2
done

echo "==> Initialising Vault..."
vault operator init -format=json > ./vault-init.json
echo "    Init complete. Keys saved to vault-init.json (gitignored)"

echo "==> Vault is using HSM Auto-Unseal — no manual unseal needed"

ROOT_TOKEN=$(cat vault-init.json | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
export VAULT_TOKEN=$ROOT_TOKEN

echo "==> Enabling Transit secrets engine (Encryption as a Service)..."
vault secrets enable transit

echo "==> Creating encryption key..."
vault write -f transit/keys/demo-key

echo "==> Setting up separation of duties policies..."

# Encrypt-only policy
vault policy write encrypt-only - <<EOF
path "transit/encrypt/demo-key" {
  capabilities = ["create", "update"]
}
EOF

# Decrypt-only policy
vault policy write decrypt-only - <<EOF
path "transit/decrypt/demo-key" {
  capabilities = ["create", "update"]
}
EOF

# Key admin policy (rotate, manage — cannot see data)
vault policy write key-admin - <<EOF
path "transit/keys/demo-key" {
  capabilities = ["read"]
}
path "transit/keys/demo-key/rotate" {
  capabilities = ["create", "update"]
}
EOF

echo "==> Creating demo tokens..."
echo "    Encrypt-only token:"
vault token create -policy=encrypt-only -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])"

echo "    Decrypt-only token:"
vault token create -policy=decrypt-only -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])"

echo "    Key-admin token:"
vault token create -policy=key-admin -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])"

echo ""
echo "==> Setup complete!"
echo "    Vault UI: http://localhost:8200"
echo "    Root token: $ROOT_TOKEN"
