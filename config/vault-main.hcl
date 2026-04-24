ui            = true
disable_mlock = true

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-main"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# PKCS#11 seal — libvault-pkcs11.so speaks KMIP to vault-hsm (port 5696).
# The library reads /etc/vault-pkcs11.hcl for KMIP server address and mTLS certs.
seal "pkcs11" {
  lib            = "/usr/local/lib/libvault-pkcs11.so"
  slot           = "0"
  pin            = "KMIP"
  key_label      = "vault-hsm-unseal-key"
  hmac_key_label = "vault-hsm-hmac-key"
  generate_key   = "true"
}

api_addr     = "http://vault-main:8200"
cluster_addr = "http://vault-main:8201"
