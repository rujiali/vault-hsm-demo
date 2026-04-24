#!/bin/bash
# Bootstrap vault-hsm: initialise (Shamir), unseal, enable KMIP secrets engine,
# create a scope/role for vault-main, and generate mTLS client credentials.
# The generated certs are written to ./certs/ and mounted into vault-main at startup.
set -e

export VAULT_ADDR=http://localhost:8201

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INIT_FILE="$SCRIPT_DIR/vault-hsm-init.json"
CERTS_DIR="$SCRIPT_DIR/certs"

mkdir -p "$CERTS_DIR"

echo "==> Waiting for vault-hsm to be ready..."
until curl -s $VAULT_ADDR/v1/sys/health 2>/dev/null | python3 -c "import sys,json; json.load(sys.stdin)" > /dev/null 2>&1; do
  sleep 2
done

INITIALIZED=$(curl -s $VAULT_ADDR/v1/sys/health | python3 -c "import sys,json; s=json.load(sys.stdin); print('true' if s.get('initialized') else 'false')")

if [ "$INITIALIZED" = "false" ]; then
  echo "==> Initialising vault-hsm (Shamir)..."
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
sleep 2

export VAULT_TOKEN=$HSM_ROOT_TOKEN

# Configure KMIP engine only on fresh initialisation
if [ "$INITIALIZED" = "false" ]; then
  echo "==> Enabling KMIP secrets engine..."
  vault secrets enable kmip

  echo "==> Configuring KMIP listener on port 5696..."
  vault write kmip/config \
    listen_addrs="0.0.0.0:5696" \
    server_hostnames="vault-hsm,localhost,127.0.0.1" \
    tls_min_version="tls12"

  echo "==> Creating KMIP scope 'sealing-key' and role 'vault-main'..."
  vault write -f kmip/scope/sealing-key

  vault write kmip/scope/sealing-key/role/vault-main \
    operation_all=true
fi

# Always regenerate client credentials so certs are fresh and match the current KMIP CA
echo "==> Generating mTLS client credentials for vault-main..."
CRED_OUTPUT=$(vault write -format=json \
  kmip/scope/sealing-key/role/vault-main/credential/generate \
  format=pem)

echo "$CRED_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['certificate'])" \
  > "$CERTS_DIR/vault-main-client-cert.pem"
echo "$CRED_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['private_key'])" \
  > "$CERTS_DIR/vault-main-client-key.pem"

echo "==> Fetching KMIP CA certificate..."
vault read -format=json kmip/ca \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ca_pem'])" \
  > "$CERTS_DIR/kmip-ca.pem"

echo ""
echo "==> vault-hsm bootstrap complete!"
echo "    vault-hsm UI   : http://localhost:8201"
echo "    Root token     : $HSM_ROOT_TOKEN"
echo "    KMIP endpoint  : vault-hsm:5696 (host: localhost:5696)"
echo "    Client certs   : ./certs/"
echo ""
echo "    Now run: docker compose up -d vault-main"
echo "    Then   : ./scripts/init.sh"
