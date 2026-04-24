# Vault HSM Demo

Demonstrates **Encryption as a Service** and **HSM integration** using two HashiCorp Vault Enterprise instances:

- `vault-hsm` — acts as the root of trust; exposes a KMIP endpoint (port 5696) used as the HSM substitute
- `vault-main` — auto-unseals via PKCS#11 (`libvault-pkcs11.so` → KMIP → `vault-hsm`), runs the Transit EaaS engine for applications

## What this demo shows

- Vault auto-unsealing via PKCS#11 seal (HSM pattern — `libvault-pkcs11.so` speaks KMIP to vault-hsm; master key never leaves vault-hsm)
- Transit engine for Encryption as a Service
- Encryption key never exposed to applications
- Key rotation with backward compatibility
- Separation of duties via Vault policies

## Prerequisites

- Docker + Docker Compose
- HashiCorp Vault Enterprise license
- `vault` CLI installed locally

## Setup

```bash
# 1. Copy env file and add your license key
cp .env.example .env
# Edit .env and set VAULT_LICENSE=<your-license>

# 2. Start vault-hsm
docker compose up -d vault-hsm

# 3. Bootstrap vault-hsm (init, unseal, create Transit key, write token to .env)
./scripts/init-hsm.sh

# 4. Start vault-main (picks up VAULT_HSM_TOKEN from .env)
docker compose up -d vault-main

# 5. Initialise vault-main (auto-unseals via vault-hsm Transit seal)
./scripts/init.sh
```

## Run the demo

```bash
./scripts/demo.sh
```

## Architecture

```
App → vault-main (Transit EaaS)
              ↓  PKCS#11 seal (libvault-pkcs11.so → KMIP)
         vault-hsm (root of trust)
         master key lives here, never exported
```

| Instance  | Port | Role |
|-----------|------|------|
| vault-hsm  | 8201 | HSM mimic — KMIP key server (port 5696), master key never exported |
| vault-main | 8200 | Application-facing — Encryption as a Service |
