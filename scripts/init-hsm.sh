#!/bin/bash
# Bootstrap vault-hsm: initialise, unseal, enable Transit, create autounseal key,
# create a scoped token for vault-main, write VAULT_HSM_TOKEN to .env
set -e

export VAULT_ADDR=http://localhost:8201

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "==> Waiting for vault-hsm to be ready..."
until curl -s $VAULT_ADDR/v1/sys/health 2>/dev/null | python3 -c "import sys,json; json.load(sys.stdin)" > /dev/null 2>&1; do
  sleep 2
done

INIT_FILE="$SCRIPT_DIR/vault-hsm-init.json"

# ---- Initialise or unseal vault-hsm ----
INITIALIZED=$(curl -s $VAULT_ADDR/v1/sys/health | python3 -c "import sys,json; s=json.load(sys.stdin); print('true' if s.get('initialized') else 'false')")

if [ "$INITIALIZED" = "false" ]; then
  echo "==> Initialising vault-hsm..."
  INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
  echo "$INIT_OUTPUT" > "$INIT_FILE"
  echo "    Init complete. Keys saved to vault-hsm-init.json (gitignored)"
else
  echo "==> vault-hsm already initialised — loading saved keys from $INIT_FILE"
  INIT_OUTPUT=$(cat "$INIT_FILE")
fi

UNSEAL_KEY=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['unseal_keys_b64'][0])")
HSM_ROOT_TOKEN=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")

echo "==> Unsealing vault-hsm..."
vault operator unseal "$UNSEAL_KEY"
sleep 1

export VAULT_TOKEN=$HSM_ROOT_TOKEN

# Only configure Transit if this is a fresh init
if [ "$INITIALIZED" = "false" ]; then
  echo "==> Enabling Transit secrets engine on vault-hsm..."
  vault secrets enable transit

  echo "==> Creating autounseal key..."
  vault write -f transit/keys/autounseal-key

  echo "==> Creating policy for vault-main auto-unseal..."
  vault policy write autounseal-policy - <<'EOF'
path "transit/encrypt/autounseal-key" {
  capabilities = ["update"]
}
path "transit/decrypt/autounseal-key" {
  capabilities = ["update"]
}
EOF
fi

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
