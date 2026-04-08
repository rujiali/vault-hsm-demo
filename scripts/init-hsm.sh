#!/bin/bash
# Bootstrap vault-hsm: initialise, unseal, enable Transit, create autounseal key,
# create a scoped token for vault-main, write VAULT_HSM_TOKEN to .env
set -e

export VAULT_ADDR=http://localhost:8201

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "==> Waiting for vault-hsm to be ready..."
until curl -sf $VAULT_ADDR/v1/sys/health > /dev/null 2>&1; do
  sleep 2
done

# ---- Initialise vault-hsm (standard Shamir — it's not using a seal) ----
echo "==> Initialising vault-hsm..."
INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
UNSEAL_KEY=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['unseal_keys_b64'][0])")
HSM_ROOT_TOKEN=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
echo "$INIT_OUTPUT" > "$SCRIPT_DIR/vault-hsm-init.json"
echo "    Init complete. Keys saved to vault-hsm-init.json (gitignored)"

echo "==> Unsealing vault-hsm..."
vault operator unseal "$UNSEAL_KEY"
sleep 1

export VAULT_TOKEN=$HSM_ROOT_TOKEN

echo "==> Enabling Transit secrets engine on vault-hsm..."
vault secrets enable transit

echo "==> Creating autounseal key..."
vault write -f transit/keys/autounseal-key \
  type=aes256-gcm96

echo "==> Creating policy for vault-main auto-unseal..."
vault policy write autounseal-policy - <<'EOF'
path "transit/encrypt/autounseal-key" {
  capabilities = ["update"]
}
path "transit/decrypt/autounseal-key" {
  capabilities = ["update"]
}
EOF

echo "==> Creating scoped token for vault-main..."
AUTOUNSEAL_TOKEN=$(vault token create \
  -policy=autounseal-policy \
  -orphan \
  -period=768h \
  -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

echo "==> Writing VAULT_HSM_TOKEN to $ENV_FILE..."
# Add or replace VAULT_HSM_TOKEN in .env
if grep -q "^VAULT_HSM_TOKEN=" "$ENV_FILE" 2>/dev/null; then
  sed -i.bak "s|^VAULT_HSM_TOKEN=.*|VAULT_HSM_TOKEN=$AUTOUNSEAL_TOKEN|" "$ENV_FILE"
  rm -f "$ENV_FILE.bak"
else
  echo "VAULT_HSM_TOKEN=$AUTOUNSEAL_TOKEN" >> "$ENV_FILE"
fi

echo ""
echo "==> vault-hsm bootstrap complete!"
echo "    vault-hsm UI  : http://localhost:8201"
echo "    Root token    : $HSM_ROOT_TOKEN"
echo "    Autounseal key: autounseal-key (Transit)"
echo ""
echo "    VAULT_HSM_TOKEN written to .env"
echo "    Now run: docker compose up -d vault-main"
echo "    Then   : ./scripts/init.sh"
