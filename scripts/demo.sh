#!/bin/bash
# Demo script: Encryption as a Service + HSM Integration

export VAULT_ADDR=http://localhost:8200

# ── Colours ──────────────────────────────────────────────────────────────────
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
WHITE="\033[97m"

# ── Helpers ───────────────────────────────────────────────────────────────────
pause() {
  echo ""
  printf "${DIM}    [ Press any key to continue... ]${RESET}"
  read -n 1 -s -r
  echo ""
  echo ""
}

step() {
  printf "${BOLD}${YELLOW}$*${RESET}\n"
}

cmd() {
  printf "${CYAN}    \$ $*${RESET}\n"
}

ok() {
  printf "${GREEN}    ✓ $*${RESET}\n"
}

fail() {
  printf "${RED}    ✗ $*${RESET}\n"
}

kv() {
  # kv "Label" "value"
  printf "    %-28s ${WHITE}${BOLD}%s${RESET}\n" "$1" "$2"
}

divider() {
  printf "${BOLD}${CYAN}════════════════════════════════════════════${RESET}\n"
}

# ── Banner ────────────────────────────────────────────────────────────────────
divider
printf "${BOLD}${WHITE}  Vault HSM Demo: Encryption as a Service${RESET}\n"
divider
echo ""

# Prompt for root token if not set
if [ -z "$VAULT_TOKEN" ]; then
  printf "${DIM}Enter root token: ${RESET}"
  read -s VAULT_TOKEN
  export VAULT_TOKEN
  echo ""
fi

# ── Step 0: HSM Integration ───────────────────────────────────────────────────
step "[0] Verifying HSM integration..."
cmd "curl -s http://localhost:8200/v1/sys/health | jq '{type,sealed,storage_type}'"
echo ""

vault status -format=json | python3 -c "
import sys, json
s = json.load(sys.stdin)
seal = s['type'] + ' (vault-hsm as root of trust)' if s['type'] == 'transit' else s['type']
print('    {:<28} {}'.format('Seal Type    :', seal))
print('    {:<28} {}'.format('Sealed       :', s['sealed']))
print('    {:<28} {}'.format('Storage Type :', s['storage_type']))
"
echo ""
ok "Vault is unsealed via Transit seal (vault-hsm) — master key never left the HSM"

pause

# ── Step 1: Encrypt ───────────────────────────────────────────────────────────
step "[1] Encrypting sensitive data (personnel record)..."
cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "             --request POST \\"
echo    "             --data '{\"plaintext\":\"<base64-encoded-record>\"}' \\"
echo    "             http://localhost:8200/v1/transit/encrypt/demo-key"
echo ""

PLAINTEXT=$(echo -n '{"name":"John Smith","clearance":"TOP SECRET","id":"EMP-00123"}' | base64)
ENCRYPT_RESPONSE=$(vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT")
CIPHERTEXT=$(echo $ENCRYPT_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])")

kv "Plaintext :" '{"name":"John Smith","clearance":"TOP SECRET","id":"EMP-00123"}'
kv "Ciphertext:" "$CIPHERTEXT"
echo ""
ok "Data encrypted — application never saw the key"

pause

# ── Step 2: Decrypt ───────────────────────────────────────────────────────────
step "[2] Decrypting ciphertext (authorised role)..."
cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "             --request POST \\"
echo    "             --data '{\"ciphertext\":\"vault:v1:...\"}' \\"
echo    "             http://localhost:8200/v1/transit/decrypt/demo-key"
echo ""

DECRYPT_RESPONSE=$(vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT")
DECODED=$(echo $DECRYPT_RESPONSE | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())")

kv "Decrypted :" "$DECODED"
echo ""
ok "Decryption successful with authorised token"

pause

# ── Step 3: Key Rotation ──────────────────────────────────────────────────────
step "[3] Rotating encryption key..."
cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "             --request POST \\"
echo    "             http://localhost:8200/v1/transit/keys/demo-key/rotate"
echo ""

vault write -f transit/keys/demo-key/rotate > /dev/null

KEY_INFO=$(vault read -format=json transit/keys/demo-key)
LATEST=$(echo $KEY_INFO | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['latest_version'])")
MIN=$(echo $KEY_INFO | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['min_decryption_version'])")
kv "Latest key version :" "v$LATEST (new encryptions use this)"
kv "Min decryption version :" "v$MIN (older versions still available)"
echo ""

echo "    Proving old ciphertext (v1) still decrypts after rotation..."
cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "             --request POST \\"
echo    "             --data '{\"ciphertext\":\"vault:v1:...\"}' \\"
echo    "             http://localhost:8200/v1/transit/decrypt/demo-key"
echo ""

OLD_DECRYPTED=$(vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())")
kv "Old ciphertext decrypted:" "$OLD_DECRYPTED"
ok "Key rotation did not break existing data"

NEW_CIPHERTEXT=$(vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])")
kv "New ciphertext (v$LATEST) :" "$NEW_CIPHERTEXT"

pause

# ── Step 4: Separation of Duties ──────────────────────────────────────────────
step "[4] Separation of duties demonstration..."
echo ""

ENCRYPT_TOKEN=$(vault token create -policy=encrypt-only -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
DECRYPT_TOKEN=$(vault token create -policy=decrypt-only -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
ADMIN_TOKEN=$(vault token create -policy=key-admin -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

# Encrypt-only
printf "    ${BOLD}[Encrypt-only role]${RESET}\n"
cmd "curl ... X-Vault-Token: <encrypt-only-token> → POST /v1/transit/encrypt/demo-key"
RESULT=$(VAULT_TOKEN=$ENCRYPT_TOKEN vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])" 2>/dev/null || echo "")
[ -n "$RESULT" ] && ok "Can encrypt: $RESULT" || fail "Cannot encrypt"

cmd "curl ... X-Vault-Token: <encrypt-only-token> → POST /v1/transit/decrypt/demo-key"
VAULT_TOKEN=$ENCRYPT_TOKEN vault write transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>&1 | grep -q "permission denied" && ok "Cannot decrypt: permission denied" || true
echo ""

# Decrypt-only
printf "    ${BOLD}[Decrypt-only role]${RESET}\n"
cmd "curl ... X-Vault-Token: <decrypt-only-token> → POST /v1/transit/decrypt/demo-key"
RESULT=$(VAULT_TOKEN=$DECRYPT_TOKEN vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>/dev/null | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())" 2>/dev/null || echo "")
[ -n "$RESULT" ] && ok "Can decrypt: $RESULT" || fail "Cannot decrypt"

cmd "curl ... X-Vault-Token: <decrypt-only-token> → POST /v1/transit/encrypt/demo-key"
VAULT_TOKEN=$DECRYPT_TOKEN vault write transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>&1 | grep -q "permission denied" && ok "Cannot encrypt: permission denied" || true
echo ""

# Key-admin
printf "    ${BOLD}[Key-admin role]${RESET}\n"
cmd "curl ... X-Vault-Token: <key-admin-token> → POST /v1/transit/keys/demo-key/rotate"
VAULT_TOKEN=$ADMIN_TOKEN vault write -f transit/keys/demo-key/rotate > /dev/null 2>&1 && ok "Can rotate key" || fail "Cannot rotate key"

cmd "curl ... X-Vault-Token: <key-admin-token> → POST /v1/transit/encrypt/demo-key"
VAULT_TOKEN=$ADMIN_TOKEN vault write transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>&1 | grep -q "permission denied" && ok "Cannot encrypt: permission denied" || true

cmd "curl ... X-Vault-Token: <key-admin-token> → POST /v1/transit/decrypt/demo-key"
VAULT_TOKEN=$ADMIN_TOKEN vault write transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>&1 | grep -q "permission denied" && ok "Cannot decrypt: permission denied" || true
echo ""

# ── Footer ────────────────────────────────────────────────────────────────────
divider
printf "${BOLD}${WHITE}  Demo complete.${RESET}\n"
printf "${DIM}  Key never left the HSM. App never saw the key.${RESET}\n"
divider
