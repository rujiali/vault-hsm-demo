# WHY UBUNTU (not the official hashicorp/vault-enterprise Alpine image):
# libvault-pkcs11.so is compiled against glibc (RHEL8/el9). Alpine uses musl libc
# and cannot load glibc binaries that use the "initial-exec" TLS model.
#
# WHY +ent.hsm BINARY:
# The standard ent binary does not include seal "pkcs11" support.
# The HSM build is required for PKCS#11 auto-unseal.
#
# WHY linux/amd64:
# vault-pkcs11-provider is only released for amd64. Docker Desktop handles
# Rosetta emulation transparently on Apple Silicon.

FROM --platform=linux/amd64 ubuntu:22.04

ARG VAULT_HSM_VERSION=2.0.0+ent.hsm
ARG PKCS11_VERSION=0.2.2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Vault Enterprise HSM binary — required for seal "pkcs11"
RUN curl -fsSL \
      "https://releases.hashicorp.com/vault/${VAULT_HSM_VERSION}/vault_${VAULT_HSM_VERSION}_linux_amd64.zip" \
      -o /tmp/vault.zip && \
    unzip /tmp/vault.zip vault -d /usr/bin/ && \
    chmod 0755 /usr/bin/vault && \
    rm /tmp/vault.zip

RUN setcap cap_ipc_lock=+ep /usr/bin/vault

# vault-pkcs11-provider — PKCS#11 library that speaks KMIP to vault-hsm
# el9 build is glibc 2.34-compatible, which works on Ubuntu 22.04 (glibc 2.35)
RUN curl -fsSL \
      "https://releases.hashicorp.com/vault-pkcs11-provider/${PKCS11_VERSION}/vault-pkcs11-provider_${PKCS11_VERSION}_linux-el9_amd64.zip" \
      -o /tmp/pkcs11.zip && \
    unzip /tmp/pkcs11.zip -d /usr/local/lib/ && \
    chmod 0755 /usr/local/lib/libvault-pkcs11.so && \
    rm /tmp/pkcs11.zip

RUN apt-get purge -y curl unzip libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /vault/data /vault/config /vault/certs

EXPOSE 8200 8201

ENTRYPOINT []
CMD ["vault", "server", "-config=/vault/config/vault.hcl"]
