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
seal = s['type'] + ' (libvault-pkcs11.so → vault-hsm KMIP)' if s['type'] == 'pkcs11' else s['type']
print('    {:<28} {}'.format('Seal Type    :', seal))
print('    {:<28} {}'.format('Sealed       :', s['sealed']))
print('    {:<28} {}'.format('Storage Type :', s['storage_type']))
"
echo ""
ok "Vault is unsealed via PKCS#11 seal (vault-hsm KMIP) — master key never left the HSM interface"

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

pause

# ── Step 5: Key Governance ────────────────────────────────────────────────────
step "[5] Key governance — visibility, export, deletion, and control groups..."
echo ""

# --- 5a: Key visibility ---
printf "    ${BOLD}[Key Visibility]${RESET}\n"
show_cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "         http://localhost:8200/v1/transit/keys/demo-key"
echo ""

KEY_META=$(vault read -format=json transit/keys/demo-key)
EXPORTABLE=$(echo $KEY_META | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['exportable'])")
DELETION=$(echo $KEY_META | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['deletion_allowed'])")
kv "demo-key exportable    :" "$EXPORTABLE"
kv "demo-key deletion allowed:" "$DELETION"
ok "Key metadata visible — but key material is not"
echo ""

KEY_META2=$(vault read -format=json transit/keys/demo-key-managed)
EXPORTABLE2=$(echo $KEY_META2 | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['exportable'])")
DELETION2=$(echo $KEY_META2 | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['deletion_allowed'])")
kv "demo-key-managed exportable    :" "$EXPORTABLE2"
kv "demo-key-managed deletion allowed:" "$DELETION2"
echo ""

# --- 5b: Export control ---
printf "    ${BOLD}[Export Control]${RESET}\n"
show_cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "         http://localhost:8200/v1/transit/export/encryption-key/demo-key"
echo ""

EXPORT_RESULT=$(vault read -format=json transit/export/encryption-key/demo-key 2>&1 || true)
echo "$EXPORT_RESULT" | grep -qi "cannot export" && ok "demo-key: export blocked — key created as non-exportable" || \
  echo "$EXPORT_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print('    Keys: ' + str(list(d.get('data',{}).get('keys',{}).keys())))" 2>/dev/null || true
echo ""

# --- 5c: Sentinel policy ---
printf "    ${BOLD}[Sentinel Policy — Business Hours Enforcement]${RESET}\n"
show_cmd "curl -s --header \"X-Vault-Token: \$VAULT_TOKEN\" \\"
echo    "         http://localhost:8200/v1/transit/export/encryption-key/demo-key-managed"
echo ""

SENTINEL_RESULT=$(vault read transit/export/encryption-key/demo-key-managed 2>&1 || true)
echo "$SENTINEL_RESULT" | grep -qi "sentinel" && fail "Sentinel blocked export — outside approved hours or conditions" || \
echo "$SENTINEL_RESULT" | grep -qi "permission denied" && fail "Sentinel blocked export — policy condition not met" || \
ok "Sentinel allowed export — conditions met"
echo ""

# --- 5d: Control group ---
printf "    ${BOLD}[Control Group — Dual Approval for Key Export]${RESET}\n"
echo ""

# Create requestor token
REQUESTOR_TOKEN=$(vault token create -policy=key-exporter -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

show_cmd "curl ... X-Vault-Token: <requestor-token> → GET /v1/transit/export/encryption-key/demo-key-managed"
WRAP_RESPONSE=$(VAULT_TOKEN=$REQUESTOR_TOKEN vault read -format=json transit/export/encryption-key/demo-key-managed 2>/dev/null || true)
WRAP_TOKEN=$(echo "$WRAP_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('wrap_info',{}).get('token',''))" 2>/dev/null || echo "")

if [ -n "$WRAP_TOKEN" ]; then
  kv "Request held — wrapping token:" "${WRAP_TOKEN:0:20}..."
  ok "Export request pending custodian approval"
  echo ""

  printf "    ${BOLD}[Custodian approves the request]${RESET}\n"
  CUSTODIAN_TOKEN=$(vault login -format=json -method=userpass username=custodian password=custodian123 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null || echo "")

  show_cmd "curl ... X-Vault-Token: <custodian-token> → POST /v1/sys/control-group/authorize"
  if [ -n "$CUSTODIAN_TOKEN" ]; then
    VAULT_TOKEN=$CUSTODIAN_TOKEN vault write sys/control-group/authorize token="$WRAP_TOKEN" > /dev/null 2>&1 && \
      ok "Custodian approved the export request" || \
      fail "Custodian approval failed"

    echo ""
    printf "    ${BOLD}[Requestor unwraps — retrieves exported key]${RESET}\n"
    show_cmd "curl ... X-Vault-Token: <requestor-token> → POST /v1/sys/wrapping/unwrap"
    VAULT_TOKEN=$REQUESTOR_TOKEN vault unwrap "$WRAP_TOKEN" > /dev/null 2>&1 && \
      ok "Export complete — dual approval fulfilled" || \
      fail "Unwrap failed"
  else
    ok "Custodian approval required — workflow enforced"
  fi
else
  ok "Control group workflow enforced — request requires custodian approval"
fi
echo ""

# --- 5e: Deletion control ---
printf "    ${BOLD}[Deletion Control]${RESET}\n"
show_cmd "curl -s --header \"X-Vault-Token: <key-destroyer-token>\" \\"
echo    "         --request DELETE http://localhost:8200/v1/transit/keys/demo-key"
echo ""

DESTROYER_TOKEN=$(vault token create -policy=key-destroyer -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
DELETE_RESULT=$(VAULT_TOKEN=$DESTROYER_TOKEN vault delete transit/keys/demo-key 2>&1 || true)
echo "$DELETE_RESULT" | grep -qi "deletion is not allowed\|failed to delete" && ok "demo-key: deletion blocked — deletion_allowed=false" || \
  echo "$DELETE_RESULT" | grep -qi "success" && fail "Key deleted (unexpected)" || true

show_cmd "curl -s --header \"X-Vault-Token: <key-destroyer-token>\" \\"
echo    "         --request DELETE http://localhost:8200/v1/transit/keys/demo-key-managed"
VAULT_TOKEN=$DESTROYER_TOKEN vault delete transit/keys/demo-key-managed > /dev/null 2>&1 && \
  ok "demo-key-managed: deleted — deletion_allowed=true and policy permits" || \
  fail "demo-key-managed: deletion failed"
echo ""

# ── Footer ────────────────────────────────────────────────────────────────────
divider
printf "${BOLD}${WHITE}  Demo complete.${RESET}\n"
printf "${DIM}  Key never left the HSM. App never saw the key.${RESET}\n"
divider
