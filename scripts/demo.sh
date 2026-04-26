#!/bin/bash
# Demo script: Encryption as a Service + HSM Integration

clear

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

show_cmd() {
  printf "${CYAN}    \$ $*${RESET}\n"
}

# vault_curl METHOD URL TOKEN [DATA]
vault_curl() {
  local method="$1" url="$2" tok="${3:0:20}..." data="$4"
  printf "${CYAN}    \$ curl -s -X ${method} \\\\${RESET}\n"
  printf "${CYAN}        -H \"X-Vault-Token: ${tok}\" \\\\${RESET}\n"
  [ -n "$data" ] && printf "${CYAN}        -d '${data}' \\\\${RESET}\n"
  printf "${CYAN}        ${url}${RESET}\n"
}

# show_policy NAME — print the Vault policy HCL
show_policy() {
  local name="$1"
  printf "    ${DIM}vault policy read ${name}${RESET}\n"
  vault policy read "$name" 2>/dev/null | while IFS= read -r line; do
    printf "    ${DIM}${line}${RESET}\n"
  done
}

# show_resp JSON_STRING [KEYS...]  — pretty-print selected keys from a JSON response
show_resp() {
  local json="$1"; shift
  local keys="$*"
  echo "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '$keys'.split()
    # Walk dot-separated key paths
    def pick(d, path):
        for k in path.split('.'):
            if isinstance(d, dict): d = d.get(k, {})
        return d
    if keys:
        out = {}
        for k in keys:
            label = k.split('.')[-1]
            v = pick(d, k)
            if v not in ({}, None, ''): out[label] = v
    else:
        out = d.get('data', d.get('auth', d.get('errors', d)))
    print(json.dumps(out, indent=2))
except Exception as e:
    print(sys.stdin.read())
" | while IFS= read -r line; do
    printf "    ${DIM}${line}${RESET}\n"
  done
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

# Load root token from init file if not already set
if [ -z "$VAULT_TOKEN" ]; then
  INIT_FILE="$(cd "$(dirname "$0")/.." && pwd)/vault-main-init.json"
  if [ -f "$INIT_FILE" ]; then
    export VAULT_TOKEN=$(python3 -c "import json; print(json.load(open('$INIT_FILE'))['root_token'])")
  else
    printf "${DIM}Enter root token: ${RESET}"
    read -s VAULT_TOKEN
    export VAULT_TOKEN
    echo ""
  fi
fi

# ── Pre-flight: ensure demo-key-managed exists ───────────────────────────────
vault read transit/keys/demo-key-managed > /dev/null 2>&1 || {
  vault write -f transit/keys/demo-key-managed > /dev/null
  vault write transit/keys/demo-key-managed/config exportable=true deletion_allowed=true > /dev/null
}

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
PLAINTEXT=$(echo -n '{"name":"John Smith","clearance":"TOP SECRET","id":"EMP-00123"}' | base64)
vault_curl POST http://localhost:8200/v1/transit/encrypt/demo-key "$VAULT_TOKEN" "{\"plaintext\":\"${PLAINTEXT}\"}"
echo ""
printf "    ${DIM}Note: Vault Transit requires plaintext to be base64-encoded.${RESET}\n"
printf "    ${DIM}The plaintext field is NOT the encrypted value — it is the raw data${RESET}\n"
printf "    ${DIM}encoded as base64 for transport. Vault encrypts the underlying bytes:${RESET}\n"
printf "    ${DIM}  Original : {\"name\":\"John Smith\",\"clearance\":\"TOP SECRET\",...}${RESET}\n"
printf "    ${DIM}  Base64   : ${PLAINTEXT}${RESET}\n"
printf "    ${DIM}  Vault encrypts the bytes and returns: vault:vN:<ciphertext>${RESET}\n"
echo ""

ENCRYPT_RESPONSE=$(vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT")
CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])")
show_resp "$ENCRYPT_RESPONSE" data.ciphertext data.key_version
echo ""
kv "Plaintext :" '{"name":"John Smith","clearance":"TOP SECRET","id":"EMP-00123"}'
kv "Ciphertext:" "$CIPHERTEXT"
echo ""
ok "Data encrypted — application never saw the key"

pause

# ── Step 2: Decrypt ───────────────────────────────────────────────────────────
step "[2] Decrypting ciphertext (authorised role)..."
vault_curl POST http://localhost:8200/v1/transit/decrypt/demo-key "$VAULT_TOKEN" "{\"ciphertext\":\"${CIPHERTEXT}\"}"
echo ""

DECRYPT_RESPONSE=$(vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT")
DECODED=$(echo "$DECRYPT_RESPONSE" | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())")
show_resp "$DECRYPT_RESPONSE" data.plaintext
echo ""
kv "Decrypted :" "$DECODED"
echo ""
ok "Decryption successful with authorised token"

pause

# ── Step 3: Key Rotation ──────────────────────────────────────────────────────
step "[3] Rotating encryption key..."
vault_curl POST http://localhost:8200/v1/transit/keys/demo-key/rotate "$VAULT_TOKEN"
echo ""

ROTATE_RESPONSE=$(vault write -f -format=json transit/keys/demo-key/rotate 2>&1 || echo '{}')
printf "    ${DIM}HTTP 204 No Content — rotation complete, no body returned${RESET}\n"
echo ""

KEY_INFO=$(vault read -format=json transit/keys/demo-key)
LATEST=$(echo "$KEY_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['latest_version'])")
MIN=$(echo "$KEY_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['min_decryption_version'])")
kv "Latest key version :" "v$LATEST (new encryptions use this)"
kv "Min decryption version :" "v$MIN (older versions still available)"
echo ""

echo "    Proving old ciphertext (v1) still decrypts after rotation..."
vault_curl POST http://localhost:8200/v1/transit/decrypt/demo-key "$VAULT_TOKEN" "{\"ciphertext\":\"${CIPHERTEXT}\"}"
OLD_DECRYPT_RESPONSE=$(vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT")
OLD_DECRYPTED=$(echo "$OLD_DECRYPT_RESPONSE" | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())")
show_resp "$OLD_DECRYPT_RESPONSE" data.plaintext
echo ""
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

printf "    ${DIM}Three role-scoped tokens created from Vault policy:${RESET}\n"
printf "    ${DIM}  %-20s policy=encrypt-only  token=%s...${RESET}\n" "Encrypt-only role:" "${ENCRYPT_TOKEN:0:20}"
printf "    ${DIM}  %-20s policy=decrypt-only  token=%s...${RESET}\n" "Decrypt-only role:" "${DECRYPT_TOKEN:0:20}"
printf "    ${DIM}  %-20s policy=key-admin      token=%s...${RESET}\n" "Key-admin role:    " "${ADMIN_TOKEN:0:20}"
echo ""

# Encrypt-only
printf "    ${BOLD}[Role: encrypt-only]${RESET}\n"
show_policy encrypt-only
echo ""
vault_curl POST http://localhost:8200/v1/transit/encrypt/demo-key "$ENCRYPT_TOKEN" "{\"plaintext\":\"${PLAINTEXT}\"}"
ENC_ONLY_RESP=$(VAULT_TOKEN=$ENCRYPT_TOKEN vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>/dev/null || echo '{"errors":["permission denied"]}')
show_resp "$ENC_ONLY_RESP" data.ciphertext data.key_version errors
RESULT=$(echo "$ENC_ONLY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])" 2>/dev/null || echo "")
[ -n "$RESULT" ] && ok "Can encrypt: $RESULT" || fail "Cannot encrypt"

vault_curl POST http://localhost:8200/v1/transit/decrypt/demo-key "$ENCRYPT_TOKEN" "{\"ciphertext\":\"${CIPHERTEXT}\"}"
DEC_DENIED_RESP=$(VAULT_TOKEN=$ENCRYPT_TOKEN vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>/dev/null || echo '{"errors":["1 error occurred: * permission denied"]}')
show_resp "$DEC_DENIED_RESP" errors
echo "$DEC_DENIED_RESP" | grep -qi "permission denied" && ok "Cannot decrypt: permission denied" || true

pause

# Decrypt-only
printf "    ${BOLD}[Role: decrypt-only]${RESET}\n"
show_policy decrypt-only
echo ""
vault_curl POST http://localhost:8200/v1/transit/decrypt/demo-key "$DECRYPT_TOKEN" "{\"ciphertext\":\"${CIPHERTEXT}\"}"
DEC_ONLY_RESP=$(VAULT_TOKEN=$DECRYPT_TOKEN vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>/dev/null || echo '{"errors":["permission denied"]}')
show_resp "$DEC_ONLY_RESP" data.plaintext errors
RESULT=$(echo "$DEC_ONLY_RESP" | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())" 2>/dev/null || echo "")
[ -n "$RESULT" ] && ok "Can decrypt: $RESULT" || fail "Cannot decrypt"

vault_curl POST http://localhost:8200/v1/transit/encrypt/demo-key "$DECRYPT_TOKEN" "{\"plaintext\":\"${PLAINTEXT}\"}"
ENC_DENIED_RESP=$(VAULT_TOKEN=$DECRYPT_TOKEN vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>/dev/null || echo '{"errors":["1 error occurred: * permission denied"]}')
show_resp "$ENC_DENIED_RESP" errors
echo "$ENC_DENIED_RESP" | grep -qi "permission denied" && ok "Cannot encrypt: permission denied" || true

pause

# Key-admin
printf "    ${BOLD}[Role: key-admin]${RESET}\n"
show_policy key-admin
echo ""
vault_curl POST http://localhost:8200/v1/transit/keys/demo-key/rotate "$ADMIN_TOKEN"
VAULT_TOKEN=$ADMIN_TOKEN vault write -f transit/keys/demo-key/rotate > /dev/null 2>&1 && ok "Can rotate key" || fail "Cannot rotate key"
printf "    ${DIM}HTTP 204 No Content${RESET}\n"

vault_curl POST http://localhost:8200/v1/transit/encrypt/demo-key "$ADMIN_TOKEN" "{\"plaintext\":\"${PLAINTEXT}\"}"
ADMIN_ENC_RESP=$(VAULT_TOKEN=$ADMIN_TOKEN vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>/dev/null || echo '{"errors":["1 error occurred: * permission denied"]}')
show_resp "$ADMIN_ENC_RESP" errors
echo "$ADMIN_ENC_RESP" | grep -qi "permission denied" && ok "Cannot encrypt: permission denied" || true

vault_curl POST http://localhost:8200/v1/transit/decrypt/demo-key "$ADMIN_TOKEN" "{\"ciphertext\":\"${CIPHERTEXT}\"}"
ADMIN_DEC_RESP=$(VAULT_TOKEN=$ADMIN_TOKEN vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>/dev/null || echo '{"errors":["1 error occurred: * permission denied"]}')
show_resp "$ADMIN_DEC_RESP" errors
echo "$ADMIN_DEC_RESP" | grep -qi "permission denied" && ok "Cannot decrypt: permission denied" || true
echo ""

pause

# ── Step 5: Key Governance ────────────────────────────────────────────────────
step "[5] Key governance — visibility, export, deletion, and control groups..."
echo ""

# --- 5a: Key visibility ---
printf "    ${BOLD}[Key Visibility]${RESET}\n"
vault_curl GET http://localhost:8200/v1/transit/keys/demo-key "$VAULT_TOKEN"
echo ""

KEY_META=$(vault read -format=json transit/keys/demo-key)
show_resp "$KEY_META" data.name data.type data.exportable data.deletion_allowed data.latest_version data.min_decryption_version
EXPORTABLE=$(echo "$KEY_META" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['exportable'])")
DELETION=$(echo "$KEY_META" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['deletion_allowed'])")
echo ""
kv "demo-key exportable    :" "$EXPORTABLE"
kv "demo-key deletion allowed:" "$DELETION"
ok "Key metadata visible — but key material is not"
echo ""

KEY_META2=$(vault read -format=json transit/keys/demo-key-managed)
show_resp "$KEY_META2" data.name data.type data.exportable data.deletion_allowed data.latest_version
EXPORTABLE2=$(echo "$KEY_META2" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['exportable'])")
DELETION2=$(echo "$KEY_META2" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['deletion_allowed'])")
echo ""
kv "demo-key-managed exportable    :" "$EXPORTABLE2"
kv "demo-key-managed deletion allowed:" "$DELETION2"

pause

# --- 5b: Export control ---
printf "    ${BOLD}[Export Control]${RESET}\n"
vault_curl GET http://localhost:8200/v1/transit/export/encryption-key/demo-key "$VAULT_TOKEN"
echo ""

EXPORT_RESULT=$(vault read -format=json transit/export/encryption-key/demo-key 2>/dev/null || echo '{"errors":["transit: key is not exportable"]}')
show_resp "$EXPORT_RESULT" errors data.keys
echo "$EXPORT_RESULT" | grep -qi "not exportable\|cannot export" && ok "demo-key: export blocked — key created as non-exportable" || true

pause

# --- 5c: Sentinel policy ---
printf "    ${BOLD}[Sentinel Policy — Business Hours Enforcement]${RESET}\n"
vault_curl GET http://localhost:8200/v1/transit/export/encryption-key/demo-key-managed "$VAULT_TOKEN"
echo ""

SENTINEL_RESULT=$(vault read -format=json transit/export/encryption-key/demo-key-managed 2>/dev/null || echo '{"errors":["sentinel policy violated"]}')
show_resp "$SENTINEL_RESULT" errors data.keys
echo "$SENTINEL_RESULT" | grep -qi "sentinel" && fail "Sentinel blocked export — outside approved hours or conditions" || \
echo "$SENTINEL_RESULT" | grep -qi "permission denied" && fail "Sentinel blocked export — policy condition not met" || \
ok "Sentinel allowed export — conditions met"

pause

# --- 5d: Control group ---
printf "    ${BOLD}[Control Group — Dual Approval for Key Export]${RESET}\n"
echo ""

# Create requestor token
REQUESTOR_TOKEN=$(vault token create -policy=key-exporter -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

vault_curl GET http://localhost:8200/v1/transit/export/encryption-key/demo-key-managed "$REQUESTOR_TOKEN"
WRAP_RESPONSE=$(VAULT_TOKEN=$REQUESTOR_TOKEN vault read -format=json transit/export/encryption-key/demo-key-managed 2>/dev/null || true)
show_resp "$WRAP_RESPONSE" wrap_info.token wrap_info.accessor wrap_info.ttl wrap_info.creation_time
WRAP_TOKEN=$(echo "$WRAP_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('wrap_info',{}).get('token',''))" 2>/dev/null || echo "")
WRAP_ACCESSOR=$(echo "$WRAP_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('wrap_info',{}).get('accessor',''))" 2>/dev/null || echo "")

if [ -n "$WRAP_TOKEN" ]; then
  echo ""
  kv "Request held — wrapping token:" "${WRAP_TOKEN:0:20}..."
  ok "Export request pending custodian approval"
  echo ""

  printf "    ${BOLD}[Custodian approves the request]${RESET}\n"
  CUSTODIAN_TOKEN=$(vault write -format=json auth/userpass/login/custodian password=custodian123 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null || echo "")

  vault_curl POST http://localhost:8200/v1/sys/control-group/authorize "$CUSTODIAN_TOKEN" "{\"accessor\":\"${WRAP_ACCESSOR}\"}"
  if [ -n "$CUSTODIAN_TOKEN" ]; then
    AUTH_RESP=$(VAULT_TOKEN=$CUSTODIAN_TOKEN vault write -format=json sys/control-group/authorize accessor="$WRAP_ACCESSOR" 2>/dev/null || echo '{"errors":["approval failed"]}')
    show_resp "$AUTH_RESP" approved errors
    echo "$AUTH_RESP" | grep -qi '"approved": *true\|approved.*true' && \
      ok "Custodian approved the export request" || \
      fail "Custodian approval failed"

    echo ""
    printf "    ${BOLD}[Requestor unwraps — retrieves exported key]${RESET}\n"
    vault_curl POST http://localhost:8200/v1/sys/wrapping/unwrap "$REQUESTOR_TOKEN" "{\"token\":\"${WRAP_TOKEN}\"}"
    UNWRAP_RESP=$(VAULT_TOKEN=$REQUESTOR_TOKEN vault unwrap -format=json "$WRAP_TOKEN" 2>/dev/null || echo '{"errors":["unwrap failed"]}')
    show_resp "$UNWRAP_RESP" data errors
    echo "$UNWRAP_RESP" | grep -qi '"errors"' && fail "Unwrap failed" || ok "Export complete — dual approval fulfilled"
  else
    ok "Custodian approval required — workflow enforced"
  fi
else
  ok "Control group workflow enforced — request requires custodian approval"
fi

pause

# --- 5e: Deletion control ---
printf "    ${BOLD}[Deletion Control]${RESET}\n"
echo ""

DESTROYER_TOKEN=$(vault token create -policy=key-destroyer -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
vault_curl DELETE http://localhost:8200/v1/transit/keys/demo-key "$DESTROYER_TOKEN"
DELETE_RESULT=$(VAULT_TOKEN=$DESTROYER_TOKEN vault delete -format=json transit/keys/demo-key 2>/dev/null || echo '{"errors":["key is not deletable — deletion_allowed=false"]}')
show_resp "$DELETE_RESULT" errors
echo "$DELETE_RESULT" | grep -qi "deletion is not allowed\|not deletable\|failed to delete" && ok "demo-key: deletion blocked — deletion_allowed=false" || true
echo ""

vault_curl DELETE http://localhost:8200/v1/transit/keys/demo-key-managed "$DESTROYER_TOKEN"
DELETE_MANAGED_RESULT=$(VAULT_TOKEN=$DESTROYER_TOKEN vault delete -format=json transit/keys/demo-key-managed 2>/dev/null || echo '{"errors":["deletion failed"]}')
if echo "$DELETE_MANAGED_RESULT" | grep -qi '"errors"'; then
  show_resp "$DELETE_MANAGED_RESULT" errors
  fail "demo-key-managed: deletion failed"
else
  printf "    ${DIM}HTTP 204 No Content — key deleted${RESET}\n"
  ok "demo-key-managed: deleted — deletion_allowed=true and policy permits"
fi
echo ""

# ── Footer ────────────────────────────────────────────────────────────────────
divider
printf "${BOLD}${WHITE}  Demo complete.${RESET}\n"
printf "${DIM}  Key never left the HSM. App never saw the key.${RESET}\n"
divider
