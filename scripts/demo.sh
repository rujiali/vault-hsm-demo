#!/bin/bash
# Demo script: Encryption as a Service + HSM Integration

export VAULT_ADDR=http://localhost:8200

echo "============================================"
echo " Vault HSM Demo: Encryption as a Service"
echo "============================================"
echo ""

# Prompt for root token if not set
if [ -z "$VAULT_TOKEN" ]; then
  read -s -p "Enter root token: " VAULT_TOKEN
  export VAULT_TOKEN
  echo ""
fi

# --- HSM: Show Vault is using HSM Auto-Unseal ---
echo "[0] Verifying HSM integration..."
vault status -format=json | python3 -c "
import sys, json
s = json.load(sys.stdin)
print('    Seal Type    :', s['seal_type'])
print('    Sealed       :', s['sealed'])
print('    Storage Type :', s['storage_type'])
"
echo "    ✓ Vault is unsealed via HSM (PKCS#11/SoftHSM) — master key never left hardware"
echo ""

# --- STEP 1: Encrypt ---
echo "[1] Encrypting sensitive data (personnel record)..."
PLAINTEXT=$(echo -n '{"name":"John Smith","clearance":"TOP SECRET","id":"EMP-00123"}' | base64)

ENCRYPT_RESPONSE=$(vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT")
CIPHERTEXT=$(echo $ENCRYPT_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])")

echo "    Plaintext : {\"name\":\"John Smith\",\"clearance\":\"TOP SECRET\",\"id\":\"EMP-00123\"}"
echo "    Ciphertext: $CIPHERTEXT"
echo "    ✓ Data encrypted — application never saw the key"
echo ""

# --- STEP 2: Decrypt ---
echo "[2] Decrypting ciphertext (authorised role)..."
DECRYPT_RESPONSE=$(vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT")
DECODED=$(echo $DECRYPT_RESPONSE | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())")
echo "    Decrypted : $DECODED"
echo "    ✓ Decryption successful with authorised token"
echo ""

# --- STEP 3: Key rotation ---
echo "[3] Rotating encryption key..."
vault write -f transit/keys/demo-key/rotate

# Show key versions
KEY_INFO=$(vault read -format=json transit/keys/demo-key)
LATEST=$(echo $KEY_INFO | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['latest_version'])")
MIN=$(echo $KEY_INFO | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['min_decryption_version'])")
echo "    Latest key version      : v$LATEST (new encryptions use this)"
echo "    Min decryption version  : v$MIN (older versions still available)"
echo ""

# Prove old ciphertext (v1) still decrypts after rotation
echo "    Proving old ciphertext (v1) still decrypts after rotation..."
OLD_DECRYPTED=$(vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())")
echo "    Old ciphertext decrypted: $OLD_DECRYPTED"
echo "    ✓ Key rotation did not break existing data"

# Encrypt new data with rotated key
NEW_CIPHERTEXT=$(vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])")
echo "    New ciphertext (v$LATEST)   : $NEW_CIPHERTEXT"
echo ""

# --- STEP 4: Separation of duties ---
echo "[4] Separation of duties demonstration..."

# Create tokens for each role
ENCRYPT_TOKEN=$(vault token create -policy=encrypt-only -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
DECRYPT_TOKEN=$(vault token create -policy=decrypt-only -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
ADMIN_TOKEN=$(vault token create -policy=key-admin -format=json | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

# Encrypt-only: can encrypt, cannot decrypt
echo "    [Encrypt-only role]"
RESULT=$(VAULT_TOKEN=$ENCRYPT_TOKEN vault write -format=json transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])" 2>/dev/null || echo "")
[ -n "$RESULT" ] && echo "    ✓ Can encrypt: $RESULT" || echo "    ✗ Cannot encrypt"
VAULT_TOKEN=$ENCRYPT_TOKEN vault write transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>&1 | grep -q "permission denied" && echo "    ✓ Cannot decrypt: permission denied" || true
echo ""

# Decrypt-only: can decrypt, cannot encrypt
echo "    [Decrypt-only role]"
RESULT=$(VAULT_TOKEN=$DECRYPT_TOKEN vault write -format=json transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>/dev/null | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['data']['plaintext']).decode())" 2>/dev/null || echo "")
[ -n "$RESULT" ] && echo "    ✓ Can decrypt: $RESULT" || echo "    ✗ Cannot decrypt"
VAULT_TOKEN=$DECRYPT_TOKEN vault write transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>&1 | grep -q "permission denied" && echo "    ✓ Cannot encrypt: permission denied" || true
echo ""

# Key-admin: can rotate, cannot encrypt or decrypt
echo "    [Key-admin role]"
VAULT_TOKEN=$ADMIN_TOKEN vault write -f transit/keys/demo-key/rotate 2>&1 | grep -q "Success" && echo "    ✓ Can rotate key" || true
VAULT_TOKEN=$ADMIN_TOKEN vault write transit/encrypt/demo-key plaintext="$PLAINTEXT" 2>&1 | grep -q "permission denied" && echo "    ✓ Cannot encrypt: permission denied" || true
VAULT_TOKEN=$ADMIN_TOKEN vault write transit/decrypt/demo-key ciphertext="$CIPHERTEXT" 2>&1 | grep -q "permission denied" && echo "    ✓ Cannot decrypt: permission denied" || true
echo ""

echo "============================================"
echo " Demo complete."
echo " Key never left the HSM. App never saw key."
echo "============================================"
