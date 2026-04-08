ui            = true
disable_mlock = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Transit seal — vault-hsm acts as the HSM / root of trust
# VAULT_TRANSIT_SEAL_TOKEN env var supplies the token at runtime
seal "transit" {
  address         = "http://vault-hsm:8200"
  # token supplied via VAULT_TRANSIT_SEAL_TOKEN environment variable
  mount_path      = "transit"
  key_name        = "autounseal-key"
  tls_skip_verify = true
}

api_addr     = "http://0.0.0.0:8200"
cluster_addr = "http://0.0.0.0:8201"
