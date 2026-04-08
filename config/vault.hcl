ui            = true
disable_mlock = false

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# HSM Auto-Unseal via PKCS#11 (SoftHSM)
seal "pkcs11" {
  lib            = "/usr/lib/softhsm/libsofthsm2.so"
  slot           = "0"
  pin            = "1234"
  key_label      = "vault-hsm-key"
  hmac_key_label = "vault-hsm-hmac-key"
  generate_key   = "true"
}

api_addr = "http://0.0.0.0:8200"
